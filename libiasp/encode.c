#include "encode.h"
#include "streambuf.h"
#include "field.h"
#include "network.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>


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


bool iasp_encode_spn(streambuf_t *sb, iasp_spn_code_t spn, bool raw)
{
    if(!raw) {
        if(!iasp_encode_field_code(sb, IASP_FIELD_SPN)) {
            return false;
        }
    }

    return iasp_encode_varint(sb, (unsigned int)spn);
}


bool iasp_encode_field_code(streambuf_t *sb, iasp_field_code_t field_code)
{
    return iasp_encode_varint(sb, (unsigned int)field_code);
}


bool iasp_encode_id(streambuf_t *sb, const iasp_identity_t *id)
{
    return iasp_encode_field_code(sb, IASP_FIELD_ID) &&
            iasp_encode_varint(sb, (unsigned int)id->spn) &&
            streambuf_write(sb, id->data, sizeof(id->data));
}


bool iasp_encode_nonce(streambuf_t *sb, const iasp_nonce_t *nonce)
{

    return iasp_encode_field_code(sb, IASP_FIELD_NONCE) &&
            streambuf_write(sb, nonce->data, sizeof(iasp_nonce_t));
}


bool iasp_encode_ids(streambuf_t *sb, const iasp_ids_t *ids)
{
    unsigned int i;

    assert(ids != NULL);

    /* do not encode empty list */
    if(ids->id_count == 0) {
        return false;
    }

    /* encode header */
    if(ids->id_count > 1) {
        if(iasp_encode_setof(sb, IASP_FIELD_ID, ids->id_count) == false) {
            return false;
        }
    }
    else /* field count == 1 */ {
        if(iasp_encode_field_code(sb, IASP_FIELD_ID) == false) {
            return false;
        }
    }

    /* encode elements */
    for(i = 0; i < ids->id_count; ++i) {
        if(!iasp_encode_varint(sb, (unsigned int)ids->id[i].spn)) {
            return false;
        }
        if(!streambuf_write(sb, ids->id[i].data, IASP_CONFIG_IDENTITY_SIZE)) {
            return false;
        }
    }

    return true;
}


bool iasp_encode_hmsg_init_hello(streambuf_t *sb, const iasp_hmsg_init_hello_t * const msg)
{
    return iasp_encode_varint(sb, IASP_HMSG_INIT_HELLO) &&
            iasp_encode_nonce(sb, &msg->inonce) &&
            iasp_encode_ids(sb, &msg->ids);
}


bool iasp_encode_hmsg_resp_hello(streambuf_t *sb, const iasp_hmsg_resp_hello_t * const msg)
{
    return iasp_encode_varint(sb, IASP_HMSG_RESP_HELLO) &&
            iasp_encode_nonce(sb, &msg->inonce) &&
            iasp_encode_nonce(sb, &msg->rnonce) &&
            iasp_encode_session_flags(sb, &msg->flags) &&
            iasp_encode_id(sb, &msg->id);
}


bool iasp_encode_hmsg_init_auth(streambuf_t *sb, const iasp_hmsg_init_auth_t * const msg)
{
    if(!iasp_encode_varint(sb, IASP_HMSG_INIT_AUTH) ||
            !iasp_encode_nonce(sb, &msg->inonce) ||
            !iasp_encode_nonce(sb, &msg->rnonce) ||
            !iasp_encode_sig(sb, &msg->sig) ||
            !iasp_encode_session_flags(sb, &msg->flags)) {
        return false;
    }

    /* encode optional fields */
    if(msg->has_dhkey && !iasp_encode_dhkey(sb, &msg->dhkey)) {
        return false;
    }
    if(msg->has_hint && !iasp_encode_hint(sb, &msg->hint)) {
        return false;
    }
    if(msg->has_pkey && !iasp_encode_pkey(sb, &msg->pkey)) {
        return false;
    }
    if(msg->has_oobsig && !iasp_encode_sig(sb, &msg->oobsig)) {
        return false;
    }

    return true;
}


bool iasp_encode_hmsg_resp_auth(streambuf_t *sb, const iasp_hmsg_resp_auth_t * const msg)
{
    if(!iasp_encode_varint(sb, IASP_HMSG_RESP_AUTH) ||
            !iasp_encode_nonce(sb, &msg->inonce) ||
            !iasp_encode_nonce(sb, &msg->rnonce) ||
            !iasp_encode_sig(sb, &msg->sig) ||
            !iasp_encode_dhkey(sb, &msg->dhkey)) {
        return false;
    }

    /* encode optional fields */
    if(msg->has_hint && !iasp_encode_hint(sb, &msg->hint)) {
        return false;
    }
    if(msg->has_pkey && !iasp_encode_pkey(sb, &msg->pkey)) {
        return false;
    }
    if(msg->has_oobsig && !iasp_encode_sig(sb, &msg->oobsig)) {
        return false;
    }

    return true;
}


bool iasp_encode_sig(streambuf_t *sb, const iasp_sig_t *sig)
{
    return iasp_encode_field_code(sb, IASP_FIELD_SIG) &&
            iasp_encode_spn(sb, sig->spn, true) &&
            iasp_encode_sigtype(sb, sig->sigtype, true) &&
            streambuf_write(sb, sig->sigdata, sig->siglen);
}


bool iasp_encode_pkey(streambuf_t *sb, const iasp_pkey_t *pkey)
{
    return iasp_encode_field_code(sb, IASP_FIELD_PKEY) &&
            iasp_encode_spn(sb, pkey->spn, true) &&
            streambuf_write(sb, pkey->pkeydata, pkey->pkeylen);
}


bool iasp_encode_dhkey(streambuf_t *sb, const iasp_pkey_t *pkey)
{
    return iasp_encode_field_code(sb, IASP_FIELD_DHKEY) &&
            iasp_encode_spn(sb, pkey->spn, true) &&
            streambuf_write(sb, pkey->pkeydata, pkey->pkeylen);
}


bool iasp_encode_sigtype(streambuf_t *sb, iasp_sigtype_t sigtype, bool raw)
{
    /* encode field code */
    if(!raw) {
        if(!iasp_encode_field_code(sb, IASP_FIELD_SIGTYPE)) {
            return false;
        }
    }

    /* encode enumeration value */
    return iasp_encode_varint(sb, (unsigned int)sigtype);
}


bool iasp_encode_session_flags(streambuf_t *sb, const iasp_session_flags_t * const flags)
{
    return iasp_encode_field_code(sb, IASP_FIELD_SESSION_FLAGS) &&
            streambuf_write(sb, &flags->byte, sizeof(flags->byte));
}


bool iasp_encode_hint(streambuf_t * sb, const iasp_hint_t * const hint)
{
    unsigned int hlen;

    assert(hint != NULL);

    hlen = (unsigned int)hint->hintlen;
    return iasp_encode_field_code(sb, IASP_FIELD_HINT) &&
            iasp_encode_varint(sb, hlen) &&
            streambuf_write(sb, hint->hintdata, hlen);
}


bool iasp_encode_address(streambuf_t *sb, const iasp_address_t * const address)
{
    const iasp_ip_t *ip;
    uint16_t port;

    assert(address != NULL);

    ip = iasp_network_address_ip(address);
    port = iasp_network_address_port(address);

    port = htons(port);

    return iasp_encode_field_code(sb, IASP_FIELD_IP) &&
            streambuf_write(sb, (uint8_t *)&port, sizeof(port)) &&
            streambuf_write(sb, ip->ipdata, sizeof(ip->ipdata));
}


bool iasp_encode_spi(streambuf_t *sb, const iasp_spi_t spi)
{
    return iasp_encode_field_code(sb, IASP_FIELD_SPI) && streambuf_write(sb, spi.spidata, sizeof(spi.spidata));
}


bool iasp_encode_hmsg_redirect(streambuf_t *sb, const iasp_hmsg_redirect_t * const msg)
{
    return iasp_encode_varint(sb, IASP_HMSG_REDIRECT) &&
            iasp_encode_id(sb, &msg->id) &&
            iasp_encode_address(sb, msg->tp_address);
}


bool iasp_encode_mgmt_req_session(streambuf_t *sb, const iasp_mgmt_req_session_t * const msg)
{
    assert(msg != NULL);

    if(!iasp_encode_varint(sb, IASP_MGMT_REQ) || !iasp_encode_spi(sb, msg->spi) ||
            !iasp_encode_address(sb, msg->peer_address)) {
        return false;
    }

    if(msg->has_my_address) {
        return iasp_encode_address(sb, msg->my_address);
    }

    return true;
}


bool iasp_encode_mgmt_install_session(streambuf_t *sb, const iasp_mgmt_install_session_t * const msg)
{
    if(!iasp_encode_varint(sb, IASP_MGMT_INSTALL) || iasp_encode_id(sb, &msg->peer_id) ||
           !iasp_encode_spi(sb, msg->peer_spi) || !iasp_encode_address(sb, msg->peer_address)) {
        return false;
    }

    if(msg->has_your_address) {
        return iasp_encode_address(sb, msg->peer_address);
    }

    return true;
}

