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

#include "libiasp/binbuf.h"
#include "libiasp/crypto.h"
#include "libiasp/streambuf.h"
#include "libiasp/encode.h"
#include "libiasp/network.h"
#include "libiasp/types.h"


/* mode handling */
typedef int (*modehandler_t)(const config_t *);
static int main_cd(const config_t *cfg);
static int main_ffd(const config_t *cfg);
static int main_tp(const config_t *cfg);
static const struct {
    const char *name;
    modehandler_t handler;
} modes[] = {
        {"CD", main_cd},
        {"FFD", main_ffd},
        {"TP", main_tp},
        {NULL, NULL},
};

/* local methods */
static bool add_key(const char *filename);

int main(int argc, char *argv[])
{
    int ret = 3;
    config_t cfg;
    modehandler_t modehandler = NULL;

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

    /* get mode */
    {
        const char *mode;
        unsigned int m = 0;

        if(config_lookup_string(&cfg, "mode", &mode) == CONFIG_FALSE) {
            fprintf(stderr, "Unspecified mode value.\n");
            goto exit;
        }

        /* find mode handler */
        while(modes[m].name != NULL) {
            if(strcmp(modes[m].name, mode) == 0) {
                modehandler = modes[m].handler;
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

    /* init crypto and read keys*/
    {
        unsigned int i;
        const config_setting_t *keys;

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
    }

    /* print supported profiles */
    {
        const iasp_spn_support_t* spns;
        unsigned int i;

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
    }

    /* run mode handler */
    ret = modehandler(&cfg);
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


static int main_cd(const config_t *cfg)
{
    printf("Executing CD mode.\n");
    return 0;
}


static int main_ffd(const config_t *cfg)
{
    printf("Executing FFD mode.\n");
    return 0;
}


static int main_tp(const config_t *cfg)
{
    printf("Executing TP mode.\n");
    return 0;
}
