#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "config.h"
#include "field.h"
#include "crypto.h"
#include "network.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


/* private methods */
static bool iasp_decode_pkey_common(streambuf_t *sb, iasp_pkey_t * const pkey, iasp_field_code_t fc);
static bool iasp_decode_check_field_code(streambuf_t *sb, iasp_field_code_t fc);


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

    return iasp_decode_nonce(sb, &msg->inonce) && iasp_decode_ids(sb, &msg->ids);
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

    return iasp_decode_nonce(sb, &msg->inonce) &&
            iasp_decode_nonce(sb, &msg->rnonce) &&
            iasp_decode_session_flags(sb, &msg->flags) &&
            iasp_decode_id(sb, &msg->id, false);
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


bool iasp_decode_sig(streambuf_t *sb, iasp_sig_t * const sig)
{
    /* check field id */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_SIG)) {
        return false;
    }

    /* decode spn */
    if(!iasp_decode_spn(sb, &sig->spn)) {
        return false;
    }

    /* decode sigtype */
    if(!iasp_decode_sigtype(sb, &sig->sigtype, true)) {
        return false;
    }

    /* get signature length */
    sig->siglen = spn_get_sign_length(sig->spn, sig->sigtype);

    /* zero buffer */
    memset(sig->sigdata, 0, sizeof(sig->sigdata));

    /* read signature data */
    return streambuf_read(sb, sig->sigdata, sig->siglen);
}


bool iasp_decode_pkey(streambuf_t *sb, iasp_pkey_t * const pkey)
{
    return iasp_decode_pkey_common(sb, pkey, IASP_FIELD_PKEY);
}


bool iasp_decode_dhkey(streambuf_t *sb, iasp_pkey_t * const pkey)
{
    return iasp_decode_pkey_common(sb, pkey, IASP_FIELD_DHKEY);
}


static bool iasp_decode_pkey_common(streambuf_t *sb, iasp_pkey_t * const pkey, iasp_field_code_t fc)
{
    /* check field id */
    if(!iasp_decode_check_field_code(sb, fc)) {
        return false;
    }

    /* decode spn */
    if(!iasp_decode_spn(sb, &pkey->spn)) {
        return false;
    }

    /* get pkey length */
    pkey->pkeylen = spn_get_pkey_length(pkey->spn, true);

    /* zero buffer */
    memset(pkey->pkeydata, 0, sizeof(pkey->pkeydata));

    /* read public key data */
    return streambuf_read(sb, pkey->pkeydata, pkey->pkeylen);
}


bool iasp_decode_hmsg_init_auth(streambuf_t *sb, iasp_hmsg_init_auth_t * const msg)
{
    /* decode required fields */
    if(!iasp_decode_nonce(sb, &msg->inonce) ||
            !iasp_decode_nonce(sb, &msg->rnonce) ||
            !iasp_decode_sig(sb, &msg->sig) ||
            !iasp_decode_session_flags(sb, &msg->flags)) {
        return false;
    }

    /* check optional fields */
    while(!streambuf_read_empty(sb)) {
        iasp_field_code_t fc;
        uint8_t byte;

        if(!streambuf_peek(sb, &byte)) {
            /* impossible to happen due to previous check */
            abort();
        }
        fc = (iasp_field_code_t)byte;

        switch(fc) {
            case IASP_FIELD_PKEY:
                if(msg->has_pkey || !iasp_decode_pkey(sb, &msg->pkey)) {
                    return false;
                }
                msg->has_pkey = true;
                break;

            case IASP_FIELD_DHKEY:
                if(msg->has_dhkey || !iasp_decode_dhkey(sb, &msg->dhkey)) {
                    return false;
                }
                msg->has_dhkey = true;
                break;

            case IASP_FIELD_SIG:
                if(msg->has_oobsig || !iasp_decode_sig(sb, &msg->oobsig)) {
                    return false;
                }
                msg->has_oobsig = true;
                break;

            case IASP_FIELD_HINT:
                if(msg->has_hint || !iasp_decode_hint(sb, &msg->hint)) {
                    return false;
                }
                msg->has_hint = true;
                break;

            default:
                return false;
        }
    }

    return true;
}


bool iasp_decode_hmsg_resp_auth(streambuf_t *sb, iasp_hmsg_resp_auth_t * const msg)
{
    /* decode required fields */
    if(!iasp_decode_nonce(sb, &msg->inonce) ||
            !iasp_decode_nonce(sb, &msg->rnonce) ||
            !iasp_decode_sig(sb, &msg->sig) ||
            !iasp_decode_dhkey(sb, &msg->dhkey)) {
        return false;
    }

    /* check optional fields */
    while(!streambuf_read_empty(sb)) {
        iasp_field_code_t fc;
        uint8_t byte;

        if(!streambuf_peek(sb, &byte)) {
            /* impossible to happen due to previous check */
            abort();
        }
        fc = (iasp_field_code_t)byte;

        switch(fc) {
            case IASP_FIELD_PKEY:
                if(msg->has_pkey || !iasp_decode_pkey(sb, &msg->pkey)) {
                    return false;
                }
                msg->has_pkey = true;
                break;

            case IASP_FIELD_SIG:
                if(msg->has_oobsig || !iasp_decode_sig(sb, &msg->oobsig)) {
                    return false;
                }
                msg->has_oobsig = true;
                break;

            case IASP_FIELD_HINT:
                if(msg->has_hint || !iasp_decode_hint(sb, &msg->hint)) {
                    return false;
                }
                msg->has_hint = true;
                break;

            default:
                return false;
        }
    }

    return true;
}


bool iasp_decode_sigtype(streambuf_t *sb, iasp_sigtype_t * const sigtype, bool raw)
{
    unsigned int i;

    /* check field code */
    if(!raw && !iasp_decode_check_field_code(sb, IASP_FIELD_SIGTYPE)) {
        return false;
    }

    /* get enumeration */
    if(!iasp_decode_varint(sb, &i)) {
        return false;
    }

    /* check enumeration value */
    if(i >= IASP_SIG_MAX) {
        return false;
    }

    /* set value */
    *sigtype = (iasp_sigtype_t)i;

    return true;
}


bool iasp_decode_session_flags(streambuf_t *sb, iasp_session_flags_t * const flags)
{
    return iasp_decode_check_field_code(sb, IASP_FIELD_SESSION_FLAGS) &&
            streambuf_read(sb, &flags->byte, sizeof(flags->byte));

}


bool iasp_decode_hint(streambuf_t *sb, iasp_hint_t * const hint)
{
    unsigned int hlen;

    /* check field code */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_HINT)) {
        return false;
    }

    /* decode hint length */
    if(!iasp_decode_varint(sb, &hlen)) {
        return false;
    }

    /* check hint length */
    if(hlen > IASP_CONFIG_MAX_HINT_SIZE) {
        return false;
    }

    /* fill hint info */
    hint->hintlen = (size_t)hlen;
    memset(hint->hintdata, 0, IASP_CONFIG_MAX_HINT_SIZE);

    /* read hint */
    return streambuf_read(sb, hint->hintdata, hlen);
}


static bool iasp_decode_check_field_code(streambuf_t *sb, iasp_field_code_t fc)
{
    iasp_field_code_t field_code;

    if(!iasp_decode_field_code(sb, &field_code)) {
        return false;
    }

    return fc == field_code;
}


bool iasp_decode_address(streambuf_t *sb, iasp_address_t * const address)
{
    iasp_ip_t ip;
    uint16_t port;

    /* check field code */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_IP)) {
        return false;
    }

    /* read port */
    if(!streambuf_read(sb, (uint8_t *)&port, sizeof(port))) {
        return false;
    }
    port = ntohs(port);

    /* read ip */
    if(!streambuf_read(sb, ip.ipdata, sizeof(ip.ipdata))) {
        return false;
    }

    /* init address */
    iasp_network_address_init(address, &ip, port);

    return true;
}


bool iasp_decode_spi(streambuf_t *sb, iasp_spi_t * const spi)
{
    /* check field code */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_SPI)) {
        return false;
    }

    /* read spi */
    return streambuf_read(sb, spi->spidata, sizeof(spi->spidata));
}


bool iasp_decode_hmsg_redirect(streambuf_t *sb, iasp_hmsg_redirect_t * const msg)
{
    assert(msg != NULL);
    return iasp_decode_id(sb, &msg->id, false) && iasp_decode_address(sb, &msg->tp_address);
}


bool iasp_decode_mgmt_req_session(streambuf_t *sb, iasp_mgmt_req_session_t * const msg)
{
    assert(msg != NULL);
    iasp_address_t decode_address = {NULL};

    /* decode mandatory fields */
    if(!iasp_decode_spi(sb, &msg->spi) || !iasp_decode_address(sb, &decode_address)) {
        return false;
    }
    memcpy(&msg->peer_address, &decode_address, sizeof(iasp_address_t));

    /* if there is something else it is inititator address */
    memset(&decode_address, 0, sizeof(iasp_address_t));
    if(!streambuf_read_empty(sb)) {
        if(!iasp_decode_address(sb, &decode_address)) {
            return false;
        }
        msg->has_my_address = true;
        memcpy(&msg->my_address, &decode_address, sizeof(iasp_address_t));
    }

    return true;
}


bool iasp_decode_mgmt_install_session(streambuf_t *sb, iasp_mgmt_install_session_t * const msg)
{
    /* decode mandatory fields */
    if(!iasp_decode_id(sb, &msg->peer_id, false) || !iasp_decode_spi(sb, &msg->peer_spi) ||
            !iasp_decode_skey(sb, &msg->skey) || !iasp_decode_address(sb, &msg->peer_address)) {
        return false;
    }

    /* decode optional my address */
    if(!streambuf_read_empty(sb)) {
        if(!iasp_decode_address(sb, &msg->your_address)) {
            return false;
        }
        msg->has_your_address = true;
    }

    return true;
}


bool iasp_decode_skey(streambuf_t *sb, iasp_skey_t * const skey)
{
    assert(skey != NULL);

    /* check field code */
    if(!iasp_decode_check_field_code(sb, IASP_FIELD_SKEY)) {
        return false;
    }

    /* decode SPN */
    if(!iasp_decode_spn(sb, &skey->spn)) {
        return false;
    }

    /* set key length */
    skey->keylen = spn_get_key_size(skey->spn);

    /* get SALT */
    if(!streambuf_read(sb, skey->salt.saltdata, sizeof(skey->salt.saltdata))) {
        return false;
    }

    /* read actual keys */
    return streambuf_read(sb, skey->ikey, skey->keylen) && streambuf_read(sb, skey->rkey, skey->keylen);
}


bool iasp_decode_mgmt_spi(streambuf_t *sb, iasp_mgmt_spi_t * const msg)
{
    return iasp_decode_spi(sb, &msg->spi);
}


bool iasp_decode_status(streambuf_t *sb, iasp_status_t * const status)
{
    uint8_t byte;

    assert(status != NULL);

    if(!(iasp_decode_check_field_code(sb, IASP_FIELD_OPSTATUS) &&
            streambuf_read(sb, &byte, sizeof(byte)))) {
        return false;
    }

    /* check value */
    if(byte >= IASP_STATUS_MAX) {
        return false;
    }

    /* save value */
    *status = (iasp_status_t)byte;
    return true;
}


bool iasp_decode_token(streambuf_t *sb, iasp_token_t * const token)
{
    uint32_t val;

    assert(token != NULL);

    if(!(iasp_decode_check_field_code(sb, IASP_FIELD_TOKEN) && streambuf_read(sb, (uint8_t *)&val, sizeof(val)))) {
        return false;
    }

    /* save value */
    *token = ntohl(val);
    return true;
}


bool iasp_decode_mgmt_token(streambuf_t *sb, iasp_mgmt_token_t * const msg)
{
    return iasp_decode_token(sb, &msg->token);
}


bool iasp_decode_mgmt_status(streambuf_t *sb, iasp_mgmt_status_t * const msg)
{

    return iasp_decode_status(sb, &msg->status);
}
