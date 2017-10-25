#include "encode.h"
#include "streambuf.h"
#include "field.h"

#include <assert.h>
#include <stdbool.h>


bool iasp_encode_varint(streambuf_t *sb, unsigned int x)
{
    streambuf_t subsb;
    uint8_t buf[IASP_CONFIG_VARINT_MAX_LENGTH];
    uint8_t byte;

    /* init substream */
    streambuf_init(&subsb, buf, 0, IASP_CONFIG_VARINT_MAX_LENGTH);

    /* encode */
    while(x > 0x7f) {
        byte = (uint8_t)(x & 0x7f);
        byte |= 0x80;
        x >>= 7;
        if(!streambuf_write(&subsb, &byte, 1)) {
            return false;
        }
    }

    /* encode last byte */
    byte = (uint8_t)(x & 0x7f);
    if(!streambuf_write(&subsb, &byte, 1)) {
        return false;
    }

    return streambuf_write_sb(sb, &subsb);
}


bool iasp_encode_setof(streambuf_t *sb, iasp_field_code_t field_code, unsigned int count)
{
    return iasp_encode_field_code(sb, IASP_FIELD_SETOF) &&
            iasp_encode_field_code(sb, field_code) &&
            iasp_encode_varint(sb, count);
}


bool iasp_encode_spn(streambuf_t *sb, iasp_spn_code_t spn)
{
    return iasp_encode_field_code(sb, IASP_FIELD_SPN) &&
            iasp_encode_varint(sb, (unsigned int)spn);
}


bool iasp_encode_field_code(streambuf_t *sb, iasp_field_code_t field_code)
{
    return iasp_encode_varint(sb, (unsigned int)field_code);
}


bool iasp_encode_id(streambuf_t *sb, iasp_spn_code_t spn, const iasp_identity_t *id)
{
    return iasp_encode_field_code(sb, IASP_FIELD_ID) &&
            iasp_encode_varint(sb, (unsigned int)spn) &&
            streambuf_write(sb, id->data, sizeof(id));
}


bool iasp_encode_nonce(streambuf_t *sb, const iasp_nonce_t *nonce)
{

    return iasp_encode_field_code(sb, IASP_FIELD_NONCE) &&
            streambuf_write(sb, nonce->data, sizeof(nonce));
}


bool iasp_encode_ids(streambuf_t *sb, const iasp_spn_support_t *spns)
{
    /* go through list just to count elements rather than allocate buffer
     * for the substream
     */
    const iasp_spn_support_t *el = spns;
    unsigned int  count = 0;

    assert(spns != NULL);

    /* count */
    while(el != NULL) {
        count++;
        el = el->next;
    }

    /* do not encode empty list */
    if(count == 0) {
        return false;
    }

    /* encode header */
    if(count > 1) {
        if(iasp_encode_setof(sb, IASP_FIELD_ID, count) == false) {
            return false;
        }
    }
    else /* field == 1 */ {
        if(iasp_encode_field_code(sb, IASP_FIELD_ID) == false) {
            return false;
        }
    }

    /* encode elements */
    el = spns;
    while(el != NULL) {
        if(!iasp_encode_varint(sb, (unsigned int)el->spn_code)) {
            return false;
        }
        if(!streambuf_write(sb, el->id.data, sizeof(iasp_identity_t))) {
            return false;
        }
        el = el->next;
    }

    return true;
}


bool iasp_encode_hmsg_init_hello(streambuf_t *sb, const iasp_spn_support_t *spns)
{
    return iasp_encode_varint(sb, IASP_HMSG_INIT_HELLO) &&
            iasp_encode_ids(sb, spns);
}


bool iasp_encode_hmsg_resp_hello(streambuf_t *sb, iasp_spn_code_t spn, const iasp_identity_t *id,
        const iasp_nonce_t *nonce)
{
    return iasp_encode_varint(sb, IASP_HMSG_RESP_HELLO) &&
                iasp_encode_id(sb, spn, id) &&
                iasp_encode_nonce(sb, nonce);
}
