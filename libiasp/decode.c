#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "config.h"
#include "field.h"
#include "crypto.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>


static bool iasp_decode_check_field_code(streambuf_t *sb, iasp_field_code_t fc)
{
    iasp_field_code_t field_code;

    if(!iasp_decode_field_code(sb, &field_code)) {
        return false;
    }

    return fc == field_code;
}


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

    if(i >= IASP_SPN_MAX || i == IASP_SPN_NONE) {
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
        /* decode ID */
        if(!iasp_decode_id(sb, &ids->id[i], true)) {
            return false;
        }
    }

    /* set count */
    ids->id_count = count;

    return true;
}


bool iasp_decode_hmsg_resp_hello(streambuf_t *sb, iasp_hmsg_resp_hello_t * const msg)
{
    assert(sb != NULL);
    assert(msg != NULL);

    return iasp_decode_id(sb, &msg->id, false) && iasp_decode_nonce(sb, &msg->rnonce);
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


bool iasp_decode_id(streambuf_t *sb, iasp_identity_t * const id, bool raw)
{
    /* check field id */
    if(!raw && !iasp_decode_check_field_code(sb, IASP_FIELD_ID)) {
        return false;
    }

    /* decode spn */
    if(!iasp_decode_spn(sb, &id->spn)) {
        return false;
    }

    /* decode key fingerprint */
    if(!streambuf_read(sb, id->data, IASP_CONFIG_IDENTITY_SIZE)) {
        return false;
    }

    return true;
}


bool iasp_decode_nonce(streambuf_t *sb, iasp_nonce_t * const nonce)
{
    /* check field id */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_NONCE)) {
        return false;
    }

    /* read nonce value */
    if(!streambuf_read(sb, nonce->data, IASP_CONFIG_NONCE_SIZE)) {
        return false;
    }

    return true;
}


bool iasp_decode_sig(streambuf_t *sb, iasp_ecsig_t * const sig)
{
    /* check field id */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_SIG)) {
        return false;
    }

    /* decode spn */
    if(!iasp_decode_spn(sb, &sig->spn)) {
        return false;
    }

    /* get signature length */
    sig->siglen = crypto_get_sign_length(sig->spn);

    /* zero buffer */
    memset(sig->sigdata, 0, sizeof(sig->sigdata));

    /* read signature data */
    return streambuf_read(sb, sig->sigdata, sig->siglen);
}


bool iasp_decode_pkey(streambuf_t *sb, iasp_pkey_t * const pkey)
{
    /* check field id */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_PKEY)) {
        return false;
    }

    /* decode spn */
    if(!iasp_decode_spn(sb, &pkey->spn)) {
        return false;
    }

    /* get pkey length */
    pkey->pkeylen = crypto_get_pkey_length(pkey->spn, true);

    /* zero buffer */
    memset(pkey->pkeydata, 0, sizeof(pkey->pkeydata));

    /* read public key data */
    return streambuf_read(sb, pkey->pkeydata, pkey->pkeylen);
}


bool iasp_decode_hmsg_init_auth(streambuf_t *sb, iasp_hmsg_init_auth_t * const msg)
{
    if(!iasp_decode_nonce(sb, &msg->inonce) ||
            !iasp_decode_nonce(sb, &msg->rnonce) ||
            !iasp_decode_sig(sb, &msg->sig)) {
        return false;
    }

    /* if something is left it should be optional pkey */
    if(!streambuf_read_empty(sb)) {
        if(!iasp_decode_pkey(sb, &msg->pkey)) {
            return false;
        }

        msg->has_pkey = true;
    }
    else {
        msg->has_pkey = false;
    }

    return true;
}


bool iasp_decode_hmsg_resp_auth(streambuf_t *sb, iasp_hmsg_resp_auth_t * const msg)
{
    return iasp_decode_pkey(sb, &msg->pkey) &&
            iasp_decode_sig(sb, &msg->sig.ecsig);
}
