#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "libiasp/binbuf.h"
#include "libiasp/crypto.h"
#include "libiasp/streambuf.h"
#include "libiasp/encode.h"


uint8_t testbuf[128];
streambuf_t sb;


int main(int argc, char *argv[])
{
    int fpkey;
    struct stat pkey_stat;
    size_t pkey_size;
    uint8_t *pkey_buf;
    binbuf_t pkey_bb;
    const iasp_spn_support_t* spns;
    unsigned int i;

    printf("IASP demo utility.\n");

    if(argc < 2) {
        printf("Usage: %s pkey\n", argv[0]);
        exit(1);
    }

    /* init crypto */
    crypto_init();

    /* read key files */
    for(i = 1; i < argc; ++i) {
        fpkey = open(argv[i], O_RDONLY);
        if(fpkey < 0) {
            perror("pkey open");
            exit(2);
        }
        if(stat(argv[i], &pkey_stat) < 0) {
            perror("pkey stat");
            exit(2);
        }
        pkey_size = pkey_stat.st_size;
        pkey_buf = malloc(pkey_size);
        if(read(fpkey, pkey_buf, pkey_size) != pkey_size) {
            fprintf(stderr, "Error reading pkey file.\n");
            exit(2);
        }
        close(fpkey);
        binbuf_init(&pkey_bb, pkey_buf, pkey_size);

        if(!crypto_add_key(&pkey_bb)) {
            printf("Crypto add key error: %s\n", argv[i]);
            exit(3);
        }

        free(pkey_buf);
    }

    printf("Supported profiles:\n");
    spns = crypto_get_supported_spns();
    while(spns != NULL) {
        printf("SPN=%d, ID: ", spns->spn_code);
        for(i = 0; i < IASP_CONFIG_IDENTITY_SIZE; ++i) {
            printf("%x", spns->id.data[i]);
        }
        printf("\n");
        spns = spns->next;
    }

    /* test encode */
    streambuf_init(&sb, testbuf, 0, 128);
    iasp_encode_ids(&sb, crypto_get_supported_spns());

    return 0;
}
