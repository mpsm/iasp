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
#include "libiasp/network.h"
#include "libiasp/types.h"


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
    iasp_ip_t ip;
    iasp_address_t myaddr, peeraddr;
    binbuf_t bb;
    const char test[] = {"test"};

    printf("IASP demo utility.\n");

    if(argc < 4) {
        printf("Usage: %s addr peer pkey1 [pkey2]\n", argv[0]);
        exit(1);
    }

    /* init crypto */
    crypto_init();

    /* init network address */
    iasp_network_ip_from_str(&ip, argv[1]);
    iasp_network_add_address(&myaddr, &ip, 1234);
    iasp_network_ip_from_str(&ip, argv[2]);
    iasp_network_address_init(&peeraddr, &ip, 1234);

    /* test send */
    bb.buf = (uint8_t *)test;
    bb.size = 4;
    if(!iasp_network_send(&myaddr, &peeraddr, &bb)) {
        printf("send failed");
    }
    else {
        printf("send ok");
    }
    printf("\n");

    /* read key files */
    for(i = 3; i < argc; ++i) {
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
            printf("%02x", spns->id.data[i]);
        }
        printf("\n");
        spns = spns->next;
    }

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

    return 0;
}
