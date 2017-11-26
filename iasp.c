#include <sys/types.h>
#include <sys/stat.h>

#include <libconfig.h>

#include <arpa/inet.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "libiasp/iasp.h"
#include "libiasp/binbuf.h"
#include "libiasp/crypto.h"
#include "libiasp/crypto-openssl.h"
#include "libiasp/streambuf.h"
#include "libiasp/encode.h"
#include "libiasp/network.h"
#include "libiasp/types.h"
#include "libiasp/session.h"
#include "libiasp/debug.h"
#include "libiasp/trust.h"

#include "pki.h"


#define IASP_BUFFER_SIZE (1024)
#define IASP_MAX_RETRIES (3)


/* error codes */
enum {
    ERROR_OK = 0,
    ERROR_ARGS = 1,
    ERROR_CONFIG = 2,
    ERROR_RUNTIME = 3,
};


/* mode context */
typedef struct {
    iasp_address_t *address;
    iasp_address_t *peer_address;
    config_t * cfg;
} modecontext_t;


/* mode handling */
typedef int (*modehandler_t)(const modecontext_t *);
static int main_cd(const modecontext_t *cfg);
static int main_ffd(const modecontext_t *cfg);
static int main_tp(const modecontext_t *cfg);
static const struct {
    const char *name;
    iasp_role_t role;
    modehandler_t handler;
} modes[] = {
        {"CD", IASP_ROLE_CD, main_cd},
        {"FFD", IASP_ROLE_FFD, main_ffd},
        {"TP", IASP_ROLE_TP, main_tp},
        {NULL, IASP_ROLE_MAX, NULL},
};


/* helper type */
typedef struct {
    size_t count;
    struct {
        iasp_pkey_t pubkey;
        iasp_identity_t id;
    } *keys;
} public_keys_t;


/* local buffer */
static uint8_t iasp_buffer[IASP_BUFFER_SIZE];

/* crypto context */
static public_keys_t public_keys;
static binbuf_t oob;

/* local event data */
static iasp_session_event_t last_event = SESSION_EVENT_MAX;
static iasp_session_t *last_event_session = NULL;

/* local methods */
static bool add_key(const char *filename);
static bool read_file(const char *filename, binbuf_t *bb);
static bool read_public_key(const char * filename, iasp_pkey_t *pkey, iasp_identity_t *id);
static bool event_wait(const iasp_session_t * const s, iasp_session_event_t e, int retries);

/* default event handler */
static void event_handler(iasp_session_t * const s, iasp_session_event_t e);
static void userdata_handler(iasp_session_t * const s, streambuf_t * data);

/* signal handler */
void signal_handler(int signum);

/* signal exit flag */
bool exitflag = false;


int main(int argc, char *argv[])
{
    int ret = ERROR_RUNTIME;
    const config_setting_t *keys;
    config_t cfg;
    iasp_address_t myaddr = {NULL};
    iasp_address_t peer_addr = {NULL};
    modehandler_t modehandler = NULL;
    modecontext_t ctx;
    iasp_role_t role;
    uint16_t peer_port;

    /* check input arguments */
    if(argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s config_file\n", argv[0]);
        exit(ERROR_ARGS);
    }

    /* install SIGINT handler */
    {
        struct sigaction newsigaction;
        newsigaction.sa_flags = 0;
        sigemptyset(&newsigaction.sa_mask);
        newsigaction.sa_handler = signal_handler;
        sigaction(SIGINT, &newsigaction, NULL);
    }

    /* set peer port */
    peer_port = IASP_DEFAULT_PORT;
    if(argc == 4) {
        int arg = atoi(argv[3]);

        if(arg < 1 || arg > UINT16_MAX) {
            fprintf(stderr, "Invalid peer port specified: %s\n", argv[3]);
            exit(ERROR_ARGS);
        }

        peer_port = (uint16_t)arg;
        argc--;
    }

    /* read peer ip */
    if(argc == 3) {
        iasp_ip_t ip;

        if(!iasp_network_ip_from_str(&ip, argv[2])) {
            fprintf(stderr, "Ivalid peer address: %s\n", argv[3]);
            exit(ERROR_ARGS);
        }

        iasp_network_address_init(&peer_addr, &ip, peer_port);
        ctx.peer_address = &peer_addr;
        debug_log("Using peer address: %s:%u\n", argv[2], peer_port);
    }
    else {
        ctx.peer_address = NULL;
    }

    /* init config */
    config_init(&cfg);
    if(!config_read_file(&cfg, argv[1])) {
        fprintf(stderr, "Config parse error (%s:%d) - %s\n",
                config_error_file(&cfg),
                config_error_line(&cfg),
                config_error_text(&cfg));
        config_destroy(&cfg);
        exit(ERROR_CONFIG);
    }

    /* get mode */
    {
        const char *mode;
        unsigned int m = 0;

        /* read mode from config */
        if(config_lookup_string(&cfg, "mode", &mode) == CONFIG_FALSE) {
            fprintf(stderr, "Unspecified mode value.\n");
            goto exit;
        }

        /* find mode handler */
        while(modes[m].name != NULL) {
            if(strcmp(modes[m].name, mode) == 0) {
                modehandler = modes[m].handler;
                role = modes[m].role;
                break;
            }
            m++;
        }

        /* check mode lookup result */
        if(modehandler == NULL) {
            fprintf(stderr, "Invalid mode: %s", mode);
            goto exit;
        }
    }

    /* init IASP */
    iasp_init(role, iasp_buffer, IASP_BUFFER_SIZE);

    /* init crypto and read keys*/
    {
        unsigned int i;

        /* read keys locations from config */
        if((keys = config_lookup(&cfg, "crypto.keys")) == NULL) {
            fprintf(stderr, "Crypto: specify at least one key in the configuration.\n");
            goto exit;
        }

        /* read keys */
        for(i = 0; i < config_setting_length(keys); ++i) {
            const char *keyfile = config_setting_get_string_elem(keys, i);

            if(keyfile == NULL) {
                continue;
            }

            /* read key from specified file */
            debug_log("Reding key file: %s\n", keyfile);
            if(!add_key(keyfile)) {
                fprintf(stderr, "Error reading key file: %s\n", keyfile);
                goto exit;
            }
        }

        /* read public keys */
        if((keys = config_lookup(&cfg, "crypto.public_keys")) != NULL) {
            size_t count = config_setting_length(keys);

            if(count == 0) {
                public_keys.keys = NULL;
            }
            else {
                public_keys.keys = malloc(sizeof(*public_keys.keys) * count);
            }
            public_keys.count = count;

            for(i = 0; i < count; ++i) {
                const char *keyfile = config_setting_get_string_elem(keys, i);

                if(keyfile == NULL) {
                    continue;
                }

                /* read key from specified file */
                debug_log("Reding public key file: %s\n", keyfile);
                if(!read_public_key(keyfile, &public_keys.keys[i].pubkey, &public_keys.keys[i].id)) {
                    fprintf(stderr, "Error reading key file: %s\n", keyfile);
                    goto exit;
                }

                /* set public keys data */
                security_add_pkey(&public_keys.keys[i].pubkey, false);
            }
        }
        else {
            fprintf(stderr, "Crypto: warning - no public keys specified.\n");
        }
    }

    /* read OOB key */
    oob.buf = NULL;
    oob.size = 0;
    if((keys = config_lookup(&cfg, "crypto.oob_key")) != NULL) {
        const char *filename = config_setting_get_string(keys);

        /* read key from file */
        debug_log("Reading OOB key: %s\n", filename);
        if(!read_file(filename, &oob)) {
            fprintf(stderr, "Error reading OOB key file\n");
            goto exit;
        }

        /* set key */
        crypto_set_oob_key(&oob);
    }

    /* add hint if present */
    {
        const char *hint;

        /* read address from config */
        if(config_lookup_string(&cfg, "hint", &hint) == CONFIG_TRUE) {
            debug_log("Setting hint: %s.\n", hint);
            iasp_set_hint(hint);
        }
        else {
            debug_log("No hint found.\n");
        }
    }

    /* init network */
    {
        const char *ip;

        /* read address from config */
        if(config_lookup_string(&cfg, "address", &ip) == CONFIG_FALSE) {
            fprintf(stderr, "Network: specify network adddress.\n");
            goto exit;
        }

        /* set network address */
        debug_log("Network: binding address %s:%d\n", ip, IASP_DEFAULT_PORT);
        if(!iasp_network_add_address_str(&myaddr, ip, IASP_DEFAULT_PORT)) {
            fprintf(stderr, "Cannot assign specified address: %s\n", ip);
            perror("network");
            goto exit;
        }
    }

    /* install event handlers */
    iasp_session_set_cb(event_handler);
    iasp_session_set_userdata_cb(userdata_handler);

    /* print supported profiles */
    {
        unsigned int i;
        iasp_ids_t ids;

        crypto_get_ids(&ids);
        debug_log("Supported %d profiles\n", ids.id_count);
        for(i = 0; i < ids.id_count; ++i) {
            debug_print_id(&ids.id[i]); debug_newline();
        }

    }

    /* run mode handler */
    ctx.cfg = &cfg;
    ctx.address = &myaddr;
    ret = modehandler(&ctx);

exit:
    config_destroy(&cfg);
    iasp_network_release_address(&myaddr);
    crypto_destroy();
    if(public_keys.keys) {
        free(public_keys.keys);
    }
    if(oob.buf) {
        free(oob.buf);
    }

    return ret;
}


static bool read_file(const char *filename, binbuf_t *bb)
{
    int fpkey;
    struct stat pkey_stat;
    size_t pkey_size;
    uint8_t *pkey_buf;

    fpkey = open(filename, O_RDONLY);
    if(fpkey < 0) {
        perror("pkey open");
        return false;
    }
    if(stat(filename, &pkey_stat) < 0) {
        perror("pkey stat");
        return false;
    }
    pkey_size = pkey_stat.st_size;
    pkey_buf = malloc(pkey_size);
    if(read(fpkey, pkey_buf, pkey_size) != pkey_size) {
        fprintf(stderr, "Error reading file %s.\n", filename);
        return false;
    }
    close(fpkey);
    binbuf_init(bb, pkey_buf, pkey_size);

    return true;
}


static bool add_key(const char *filename)
{
    binbuf_t pkey_bb;

    if(!read_file(filename, &pkey_bb)) {
        return false;
    }

    if(!crypto_openssl_add_key(&pkey_bb)) {
        printf("Crypto add key error: %s\n", filename);
        return false;
    }

    free(pkey_bb.buf);

    return true;
}


static bool read_public_key(const char * filename, iasp_pkey_t *pkey, iasp_identity_t *id)
{
    binbuf_t pkey_bb;

    if(!read_file(filename, &pkey_bb)) {
        return false;
    }

    if(!crypto_openssl_extract_key_bb(pkey, id, &pkey_bb)) {
        return false;
    }

    free(pkey_bb.buf);

    return true;

}


static bool cd_get_tpid(const config_t * const cfg, iasp_identity_t * const id)
{
    const config_setting_t *tpid;
    uint64_t id64;
    uint32_t id32[2];

    tpid = config_lookup(cfg, "cd.trusted_tp");
    if(tpid == NULL) {
        return false;
    }

    /* check list count */
    if(config_setting_length(tpid) != 2) {
        goto invalid_setting;
    }

    /* get SPN */
    id->spn = config_setting_get_int_elem(tpid, 0);

    /* get ID data */
    id64 = config_setting_get_int64_elem(tpid, 1);
    id32[0] = htonl((uint32_t)(id64 >> 32));
    id32[1] = htonl((uint32_t)(id64 & 0xFFFFFFFF));
    memcpy(id->data, id32, sizeof(id));
    goto ok;

invalid_setting:
    fprintf(stderr, "Invalid trusted_tp setting.\n");
    return false;

ok:
    return true;
}



static int main_cd(const modecontext_t *ctx)
{
    iasp_address_t tpaddr = {NULL};
    int ret = ERROR_RUNTIME;
    iasp_identity_t tpid;

    printf("\nExecuting CD mode.\n\n");

    /* get TP address from config */
    {
        const char *tpaddress_str;

        if(config_lookup_string(ctx->cfg, "cd.tpaddress", &tpaddress_str) == CONFIG_FALSE) {
            fprintf(stderr, "CD: specify TP address in configuration");
            ret = ERROR_CONFIG;
            goto exit;
        }

        if(!iasp_network_address_init_str(&tpaddr, tpaddress_str, IASP_DEFAULT_PORT)) {
            fprintf(stderr, "CD: invalid TP address %s", tpaddress_str);
            ret = ERROR_CONFIG;
            goto exit;
        }

        debug_log("CD: Trust Point address: %s\n", tpaddress_str);
        iasp_set_tpaddr(&tpaddr);
    }

    /* set trusted TP */
    {
        if(cd_get_tpid(ctx->cfg, &tpid)) {
            debug_log("Setting trusted TP ID: ");
            debug_print_id(&tpid);
            debug_newline();
            iasp_trust_set_tp(&tpid);
        }
    }

    {
        const iasp_session_t *tpses, *peerses;
        
        /* set TP session */
        tpses = iasp_session_start(ctx->address, &tpaddr);
        if(!event_wait(tpses, SESSION_EVENT_ESTABLISHED, 3)) {
            debug_log("Could not establish TP session.\n");
            goto exit;
        }

        /* set peer session */
        if(ctx->peer_address != NULL) {
            peerses = iasp_session_start(ctx->address, ctx->peer_address);
            if(peerses == NULL) {
                debug_log("Could not create peer session.\n");
                goto exit;
            }

            if(!event_wait(peerses, SESSION_EVENT_ESTABLISHED, 5)) {
                debug_log("Could not establish peer session.\n");
                goto exit;
            }
        }
    }

    {
        /* process incoming messages */
        for(;;) {
            iasp_session_handle_any();
            if(exitflag) {
                break;
            }
        }
    }

    ret = ERROR_OK;

exit:
    iasp_network_address_destroy(&tpaddr);

    return ret;
}


static int main_ffd(const modecontext_t *ctx)
{
    iasp_address_t tpaddr = {NULL};
    int ret = ERROR_RUNTIME;

    printf("\nExecuting FFD mode.\n\n");

    /* get TP address from config */
    {
        const char *tpaddress_str;

        if(config_lookup_string(ctx->cfg, "ffd.tpaddress", &tpaddress_str) == CONFIG_FALSE) {
            fprintf(stderr, "FFD: specify TP address in configuration");
            ret = ERROR_CONFIG;
            goto exit;
        }

        if(!iasp_network_address_init_str(&tpaddr, tpaddress_str, IASP_DEFAULT_PORT)) {
            fprintf(stderr, "FFD: invalid TP address %s", tpaddress_str);
            ret = ERROR_CONFIG;
            goto exit;
        }

        debug_log("FFD: Trust Point address: %s\n", tpaddress_str);
    }

    {
        const iasp_session_t *tpses;
        
        tpses = iasp_session_start(ctx->address, &tpaddr);
        if(!event_wait(tpses, SESSION_EVENT_ESTABLISHED, 3)) {
            debug_log("Could not establish TP session.\n");
            goto exit;
        }
    }

    ret = ERROR_OK;

exit:
    iasp_network_address_destroy(&tpaddr);

    return ret;
}


static int main_tp(const modecontext_t *ctx)
{
    printf("Executing TP mode.\n");

    pki_init();

    {
        const char *cafile;

        if(config_lookup_string(ctx->cfg, "crypto.cafile", &cafile) == CONFIG_FALSE) {
            fprintf(stderr, "TP: specify cacert.pem in configuration.\n");
            return ERROR_CONFIG;
        }
        debug_log("Adding CA file: %s.\n", cafile);
        if(!pki_lookup(cafile, NULL)) {
            return ERROR_CONFIG;
        }
    }

    {
        const char *crlfile;

        if(config_lookup_string(ctx->cfg, "crypto.crlfile", &crlfile) == CONFIG_TRUE) {
            debug_log("Adding CRL flle: %s.\n", crlfile);
            if(!pki_crl(crlfile)) {
                debug_log("Cannot add CRL file.\n");
            }
        }
    }

    {
        const config_setting_t *certs;
        unsigned int i;

        if((certs = config_lookup(ctx->cfg, "crypto.certs")) != NULL) {
            size_t count = config_setting_length(certs);
            for(i = 0; i < count; ++i) {
                const char *cert;

                cert = config_setting_get_string_elem(certs, i);
                debug_log("Adding certificate to store: %s.\n", cert);
                if(!pki_load_cert(cert)) {
                    debug_log("Failed to add certificate.\n");
                }
            }
        }
    }

    for(;;) {
        switch(iasp_session_handle_any()) {
            case SESSION_CMD_TIMEOUT:
                break;

            case SESSION_CMD_OK:
                debug_log("Message processing OK.\n");
                break;

            default:
                debug_log("Message processing error.\n");
                break;
        }

        if(exitflag) {
            iasp_session_destroy();
            break;
        }
    }

    return ERROR_OK;
}


static void event_handler(iasp_session_t * const s, iasp_session_event_t e)
{
    debug_log("Event %d received for session %p.\n", e, s);

    /* save last event details */
    last_event_session = s;
    last_event = e;

    /* process event */
    switch(e) {
        case SESSION_EVENT_ESTABLISHED:
            debug_log("Session established.\n");
            debug_newline();
            debug_print_session(s);
            debug_newline();
            iasp_session_send_userdata(s, (const uint8_t *)"test", 4);
            break;

        case SESSION_EVENT_TERMINATED:
            debug_log("Session terminated.\n");
            break;

        case SESSION_EVENT_REDIRECT:
            debug_log("Session redirect.\n");
            break;

        default:
            debug_log("Unknown event!\n");
    }
}



static bool event_wait(const iasp_session_t * const s, iasp_session_event_t e,
        int max_retries)
{
    unsigned int i;
    int retries;

    /* set retries count */
    if(max_retries == -1) {
        retries = UINT_MAX;
    }
    else {
        retries = max_retries;
    }

    /* process incoming messages */
    for(i = 0; i < retries;) {
        switch(iasp_session_handle_any()) {
            case SESSION_CMD_TIMEOUT:
                i++;
                break;

            case SESSION_CMD_OK:
                if(last_event == e) {
                    if(s != NULL && s != last_event_session) {
                        continue;
                    }
                    return true;
                }
                break;

            default:
                debug_log("Session processing error (%p).\n", s);
                return false;
        }
    }

    debug_log("Session processing timeout (%p).\n", s);
    return false;
}


bool security_use_hint(const iasp_hint_t * const hint)
{
    if(iasp_get_role() == IASP_ROLE_CD) {
        debug_log("Skipping heavy operation for CD device.\n");
        return true;
    }

    debug_log("Loading certificate from hint: %s.\n", (const char *)hint->hintdata);
    return pki_load_cert((const char*)hint->hintdata);
}


static void userdata_handler(iasp_session_t * const s, streambuf_t * data)
{
    debug_log("User data received for session: %p.\n", s);
    debug_print_binary(data->data, data->size);
    debug_newline();
}


void signal_handler(int signum)
{
    printf("\nSignal received: %d\n", signum);
    exitflag = true;
}
