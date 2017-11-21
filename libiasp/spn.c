#include "spn.h"
#include "types.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


static const struct {
    uint8_t eclen;
    uint8_t dlen;
    uint8_t keysize;
} spn_info[IASP_SPN_MAX] = {
        {0, 0, 0},
        {32, 32, 16},
        {66, 64, 32},
};


size_t spn_get_key_size(iasp_spn_code_t spn)
{
    assert(spn < IASP_SPN_MAX);
    return spn_info[spn].keysize;
}


size_t spn_get_sign_length(iasp_spn_code_t spn, iasp_sigtype_t sigtype)
{
    assert(spn < IASP_SPN_MAX);
    switch(sigtype) {
        case IASP_SIG_EC:
            return spn_info[spn].eclen * 2;

        case IASP_SIG_HMAC:
            return spn_info[spn].dlen;

        default:
            abort();
    }

    return 0;
}


size_t spn_get_pkey_length(iasp_spn_code_t spn, bool compressed)
{
    assert(spn < IASP_SPN_MAX);
    size_t dlen = spn_info[spn].eclen;

    if(compressed) {
        return dlen + 1;
    }
    else {
        return dlen * 2 + 1;
    }
}

