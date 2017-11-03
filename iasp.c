#include <sys/types.h>
#include <sys/stat.h>

#include <libconfig.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libiasp/iasp.h"
#include "libiasp/binbuf.h"
#include "libiasp/crypto.h"
#include "libiasp/crypto-openssl.h"
#include "libiasp/streambuf.h"
#include "libiasp/encode.h"
#include "libiasp/network.h"
#include "libiasp/types.h"
#include "libiasp/session.h"


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


/* local buffer */
#define IASP_BUFFER_SIZE (1024)
static uint8_t iasp_buffer[IASP_BUFFER_SIZE];


/* local methods */
static bool add_key(const char *filename);
static bool read_file(const char *filename, binbuf_t *bb);
static bool read_public_key(const char * filename, iasp_pkey_t *pkey, iasp_identity_t *id);


/* crypto context */
static crypto_public_keys_t public_keys;


int main(int argc, char *argv[])
{
    int ret = ERROR_RUNTIME;
    config_t cfg;
    iasp_address_t myaddr = {NULL};
    modehandler_t modehandler = NULL;
    modecontext_t ctx;
    iasp_role_t role;

    /* check input arguments */
    if(argc != 2) {
        fprintf(stderr, "Usage: %s config_file\n", argv[0]);
        exit(ERROR_ARGS);
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
        const config_setting_t *keys;

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
            printf("Reding key file: %s\n", keyfile);
            if(!add_key(keyfile)) {
                fprintf(stderr, "Error reading key file: %s\n", keyfile);
                goto exit;
            }
        }

        /* read public keys */
        if((keys = config_lookup(&cfg, "crypto.public_keys")) != NULL) {
            size_t count = config_setting_length(keys);

            public_keys.keys = malloc(sizeof(*public_keys.keys) * count);
            public_keys.count = count;

            for(i = 0; i < count; ++i) {
                const char *keyfile = config_setting_get_string_elem(keys, i);

                if(keyfile == NULL) {
                    continue;
                }

                /* read key from specified file */
                printf("Reding public key file: %s\n", keyfile);
                if(!read_public_key(keyfile, &public_keys.keys[i].pubkey, &public_keys.keys[i].id)) {
                    fprintf(stderr, "Error reading key file: %s\n", keyfile);
                    goto exit;
                }
            }

            /* set public keys data */
            crypto_set_pubkeys(&public_keys);
        }
        else {
            fprintf(stderr, "Crypto: warning - no public keys specified.\n");
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
        printf("Network: binding address %s:%d\n", ip, IASP_DEFAULT_PORT);
        if(!iasp_network_add_address_str(&myaddr, ip, IASP_DEFAULT_PORT)) {
            fprintf(stderr, "Cannot assign specified address: %s\n", ip);
            perror("network");
            goto exit;
        }
    }

    /* print supported profiles */
    {
        const iasp_spn_support_t* spns;
        unsigned int i;

        printf("Supported profiles:\n");

        spns = crypto_get_supported_spns();
        while(spns != NULL) {
            printf("SPN=%d, ID: ", spns->id.spn);
            for(i = 0; i < IASP_CONFIG_IDENTITY_SIZE; ++i) {
                printf("%02x", spns->id.data[i]);
            }
            printf("\n");
            spns = spns->next;
        }
    }

    /* run mode handler */
    ctx.cfg = &cfg;
    ctx.address = &myaddr;
    ret = modehandler(&ctx);

exit:
    config_destroy(&cfg);
    iasp_network_release_address(&myaddr);

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

    if(!crypto_add_key(&pkey_bb)) {
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

    if(!crypto_openssl_extract_key(pkey, id, &pkey_bb)) {
        return false;
    }

    free(pkey_bb.buf);

    return true;

}


#define CDBUFSIZE
static int main_cd(const modecontext_t *ctx)
{
    iasp_address_t tpaddr = {NULL};
    int ret = ERROR_RUNTIME;

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

        printf("CD: Trust Point address: %s\n", tpaddress_str);
    }

    {
        iasp_session_start(ctx->address, &tpaddr);
    }

    ret = ERROR_OK;

exit:
    iasp_network_address_destroy(&tpaddr);

    return ret;
}


static int main_ffd(const modecontext_t *ctx)
{
    printf("Executing FFD mode.\n");
    return ERROR_OK;
}


static int main_tp(const modecontext_t *ctx)
{
    printf("Executing TP mode.\n");

    iasp_session_handle_addr(ctx->address);
    iasp_session_handle_addr(ctx->address);

    return ERROR_OK;
}
