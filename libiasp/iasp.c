#include "iasp.h"
#include "proto.h"
#include "crypto.h"


void iasp_init(uint8_t *buf, size_t bufsize)
{
    crypto_init();
    iasp_proto_init(buf, bufsize);
}
