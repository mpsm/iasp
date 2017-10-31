#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "config.h"
#include "field.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>


bool iasp_decode_varint(streambuf_t *sb, unsigned int *i)
{
    uint8_t byte;
    unsigned int n = 0;
    unsigned vi = 0;
    unsigned int shift = 0;
    bool ret;

    assert(sb != NULL);
    assert(i != NULL);

    while((ret = streambuf_read(sb, &byte, sizeof(byte))) != false) {
        n++;
        if(n > IASP_CONFIG_VARINT_MAX_LENGTH) {
            return false;
        }

        vi += (unsigned int)(byte & 0x7f) << shift;

        if((byte & 0x80) == 0) {
            break;
        }

        shift += 7;
    }

    *i = vi;

    return ret;
}


bool iasp_decode_field_code(streambuf_t *sb, iasp_field_code_t *field_code)
{
    unsigned int vi;

    assert(field_code != NULL);

    if(!iasp_decode_varint(sb, &vi)) {
        return false;
    }

    *field_code = (iasp_field_code_t)vi;

    return true;
}


bool iasp_decode_hmsg_code(streambuf_t *sb, iasp_handshake_msg_code_t *hmsg_code)
{
    unsigned int vi;

    assert(hmsg_code != NULL);

    if(!iasp_decode_varint(sb, &vi)) {
        return false;
    }

    *hmsg_code = (iasp_handshake_msg_code_t)vi;

    return true;
}


bool iasp_decode_hmsg_init_hello(streambuf_t *sb, iasp_hmsg_init_hello_t * const msg)
{
    assert(sb != NULL);
    assert(msg != NULL);

    return iasp_decode_ids(sb, &msg->ids);
}


bool iasp_decode_spn(streambuf_t *sb, iasp_spn_code_t *spn)
{
    unsigned int i;

    if(!iasp_decode_varint(sb, &i)) {
        return false;
    }

    if(i >= IASP_SPN_MAX) {
        return false;
    }

    *spn = (iasp_spn_code_t)i;

    return true;
}


bool iasp_decode_ids(streambuf_t *sb, iasp_ids_t *ids)
{
    unsigned int count;
    unsigned int i;

    /* get count of IDs */
    if(!iasp_decode_setof(sb, IASP_FIELD_ID, &count)) {
        return false;
    }

    /* boundary check */
    if(count > IASP_MAX_IDS) {
        return false;
    }

    /* decode ids */
    for(i = 0; i < count; ++i) {
        iasp_spn_code_t spn;

        /* decode spn */
        if(!iasp_decode_spn(sb, &spn)) {
            return false;
        }
        ids->id[i].spn = spn;

        /* decode key fingerprint */
        if(!streambuf_read(sb, ids->id[i].data, IASP_CONFIG_IDENTITY_SIZE)) {
            return false;
        }
    }

    /* set count */
    ids->id_count = count;

    return true;
}

bool iasp_decode_hmsg_resp_hello(streambuf_t *sb, iasp_hmsg_resp_hello_t * const msg)
{


    return true;
}


bool iasp_decode_setof(streambuf_t *sb, iasp_field_code_t field_code, unsigned int *count)
{
    uint8_t byte;
    iasp_field_code_t fc;

    if(!streambuf_read(sb, &byte, sizeof(byte))) {
        return false;
    }

    fc = (iasp_field_code_t)byte;

    /* set count */
    if(fc != IASP_FIELD_SETOF) {
        if(fc == field_code) {
            *count = 1;
        }
        else {
            return false;
        }
    }
    else {
        if(!streambuf_read(sb, &byte, sizeof(byte))) {
            return false;
        }
        fc = (iasp_field_code_t)byte;
        if(fc != field_code) {
            return false;
        }

        if(!iasp_decode_varint(sb, count)) {
            return false;
        }
    }

    return true;
}
