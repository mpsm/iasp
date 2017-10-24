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
    //const iasp_identity_t *id;
    //int i;

    printf("IASP demo utility.\n");

    if(argc < 2) {
        printf("Usage: %s pkey\n", argv[0]);
        exit(1);
    }

    /* read key file */
    fpkey = open(argv[1], O_RDONLY);
    if(fpkey < 0) {
        perror("pkey open");
        exit(2);
    }
    if(stat(argv[1], &pkey_stat) < 0) {
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

    /* init crypto */
    crypto_init();
    if(!crypto_add_key(&pkey_bb)) {
        printf("Crypto init error.\n");
        exit(3);
    }
#if 0
    /* my id */
    id = crypto_get_id();
    printf("ID: ");
    for(i = 0; i < IASP_CONFIG_IDENTITY_SIZE; ++i) {
        printf("%x", id->data[i]);
    }
    printf("\n");

    /* test encode */
    streambuf_init(&sb, testbuf, 0, 128);
    iasp_encode_id(&sb, id);
#endif
    free(pkey_buf);


    return 0;
}
