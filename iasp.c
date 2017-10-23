#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "libiasp/binbuf.h"
#include "libiasp/crypto.h"


int main(int argc, char *argv[])
{
    int fpkey;
    struct stat pkey_stat;
    size_t pkey_size;
    uint8_t *pkey_buf;
    binbuf_t pkey_bb;

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
    crypto_init(&pkey_bb);


    free(pkey_buf);


    return 0;
}
