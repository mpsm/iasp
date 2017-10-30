#include <sys/types.h>
#include <sys/stat.h>

#include <libconfig.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "libiasp/binbuf.h"
#include "libiasp/crypto.h"
#include "libiasp/streambuf.h"
#include "libiasp/encode.h"
#include "libiasp/network.h"
#include "libiasp/types.h"


/* local methods */
static bool add_key(const char *filename);

/* local variables */
uint8_t testbuf[128];
streambuf_t sb;


int main(int argc, char *argv[])
{
    const iasp_spn_support_t* spns;
    unsigned int i;
    int ret = 3;

    /* config variables */
    config_t cfg;
    const config_setting_t *keys;

    /* check input arguments */
    if(argc != 2) {
        fprintf(stderr, "Usage: %s config_file\n", argv[0]);
        exit(1);
    }

    /* init config */
    config_init(&cfg);
    if(!config_read_file(&cfg, argv[1])) {
        fprintf(stderr, "Config parse error (%s:%d) - %s\n",
                config_error_file(&cfg),
                config_error_line(&cfg),
                config_error_text(&cfg));
        config_destroy(&cfg);
        exit(2);
    }

#if 0
    /* init network address */
    iasp_network_ip_from_str(&ip, argv[1]);
    iasp_network_add_address(&myaddr, &ip, 1234);
    iasp_network_ip_from_str(&ip, argv[2]);
    iasp_network_address_init(&peeraddr, &ip, 1234);
#endif

    /* init crypto */
    crypto_init();
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

    printf("Supported profiles:\n");

    spns = crypto_get_supported_spns();
    while(spns != NULL) {
        printf("SPN=%d, ID: ", spns->spn_code);
        for(i = 0; i < IASP_CONFIG_IDENTITY_SIZE; ++i) {
            printf("%02x", spns->id.data[i]);
        }
        printf("\n");
        spns = spns->next;
    }

#if 0
    /* test encode */
    {
        iasp_nonce_t nonce;

        streambuf_init(&sb, testbuf, 0, 128);
        iasp_encode_hmsg_init_hello(&sb, crypto_get_supported_spns());

        crypto_gen_nonce(&nonce);
        streambuf_reset(&sb);
        iasp_encode_hmsg_resp_hello(&sb, crypto_get_supported_spns()->spn_code,
                &crypto_get_supported_spns()->id, &nonce);
    }

    iasp_network_release_address(&myaddr);
#endif

    ret = 0;
exit:
    config_destroy(&cfg);
    return ret;
}


static bool add_key(const char *filename)
{
    int fpkey;
    struct stat pkey_stat;
    size_t pkey_size;
    uint8_t *pkey_buf;
    binbuf_t pkey_bb;

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
        fprintf(stderr, "Error reading pkey file.\n");
        return false;
    }
    close(fpkey);
    binbuf_init(&pkey_bb, pkey_buf, pkey_size);

    if(!crypto_add_key(&pkey_bb)) {
        printf("Crypto add key error: %s\n", filename);
        return false;
    }

    free(pkey_buf);

    return true;
}
