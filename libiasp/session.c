#include "session.h"

#include "iasp.h"
#include "crypto.h"
#include "encode.h"
#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "tp.h"
#include "ffd.h"
#include "debug.h"
#include "trust.h"
#include "role.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#define IASP_SESSION_RECV_TIMEOUT (1000)


/* session handler */
typedef bool (*iasp_session_handler_t)(iasp_session_t * const, streambuf_t * const);

/* event handler */
static iasp_session_cb_t event_cb;

/* session data */
static iasp_session_t sessions[IASP_CONFIG_MAX_SESSIONS];

/* rx/tx message structure */
static iasp_msg_storage_t msg;
static iasp_role_t role;

/* private methods */
static void iasp_reset_message(void);
static iasp_session_result_t iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload);
static bool iasp_session_generate_secret(iasp_session_t *s, const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx);;
static iasp_session_t *iasp_session_by_peer(const iasp_address_t * const peer);
static iasp_session_t *iasp_session_by_peer_ip(const iasp_address_t * const peer);

/* message handlers - handshake */
static bool iasp_handler_init_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_init_auth(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_auth(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_redirect(iasp_session_t * const, streambuf_t * const);

/* message handlers - management */
static bool iasp_handler_mgmt_req(iasp_session_t * const, streambuf_t * const);


/* lookup table */
#define MSG_CODE(X, Y) (((uint16_t)X << 8) + Y)
typedef struct {
    uint16_t msg;
    iasp_session_handler_t handler;
} session_handler_lookup_t;


/* CD handlers */
static const session_handler_lookup_t cd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_REDIRECT), iasp_handler_redirect},
        {0, NULL},
};

/* FFD handlers */
static const session_handler_lookup_t ffd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_REDIRECT), iasp_handler_redirect},
        {0, NULL},
};

/* TP handlers */
static const session_handler_lookup_t tp_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_REQ), iasp_handler_mgmt_req},
        {0, NULL},
};

const session_handler_lookup_t *handlers[IASP_ROLE_MAX] =
{
        cd_session_handlers, ffd_session_handlers, tp_session_handlers
};


void iasp_session_set_cb(iasp_session_cb_t cb)
{
    assert(cb != NULL);
    event_cb = cb;
}


void iasp_sessions_reset()
{
    memset(sessions, 0, IASP_CONFIG_MAX_SESSIONS * sizeof(iasp_session_t));
}


void iasp_session_set_role(iasp_role_t r)
{
    assert(role < IASP_ROLE_MAX);
    role = r;
}


iasp_session_t *iasp_session_new(const iasp_address_t *addr, const iasp_address_t *peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        if(sessions[i].active == false) {
            iasp_session_t *s = &sessions[i];

            iasp_session_init(s, role, addr, peer);
            debug_log("Created new session: %p\n", s);
            return s;
        }
    }

    return NULL;
}


void iasp_session_init(iasp_session_t * const this, iasp_role_t srole, const iasp_address_t *addr, const iasp_address_t *peer_addr)
{
    assert(addr != NULL);
    assert(peer_addr != NULL);

    memset(this, 0, sizeof(iasp_session_t));

    this->active = true;
    iasp_proto_ctx_init(&this->pctx);
    iasp_network_address_dup(addr, &this->pctx.addr);
    iasp_network_address_dup(peer_addr, &this->pctx.peer);

    switch(srole) {
        case IASP_ROLE_TP:
        {
            iasp_tpdata_t *tpd = NULL;

            iasp_tpdata_init(&tpd);
            this->aux = tpd;
            break;
        }

        default:
            break;
    }
}


const iasp_session_t * iasp_session_start(const iasp_address_t *addr, const iasp_address_t *peer)
{
    streambuf_t *sb;
    iasp_session_t *s;

    assert(addr != NULL);
    assert(peer != NULL);

    /* get new session */
    s = iasp_session_new(addr, peer);
    if(s == NULL) {
        abort();
    }

    /* prepare headers */
    s->pctx.msg_type = IASP_MSG_HANDSHAKE;

    /* get payload space */
    iasp_proto_reset_payload();
    sb = iasp_proto_get_payload_sb();

    /* encode hello message - set nonce and ids*/
    iasp_reset_message();
    crypto_gen_nonce(&msg.hmsg_init_hello.inonce);
    memcpy(&s->sides[SESSION_SIDE_INITIATOR].nonce, &msg.hmsg_init_hello.inonce, sizeof(iasp_nonce_t));
    crypto_get_ids(&msg.hmsg_init_hello.ids);
    if(!iasp_encode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        abort();
    }

    /* proto send message */
    if(!iasp_proto_send(&s->pctx, NULL)) {
        /* TODO: destroy session or retry */
        return NULL;
    }

    return s;
}


iasp_session_result_t iasp_session_handle_any()
{
    iasp_address_t addr = { NULL };

    return iasp_session_handle_addr(&addr);
}


iasp_session_result_t iasp_session_handle_addr(iasp_address_t * const addr)
{
    iasp_proto_ctx_t pctx;
    streambuf_t *sb;

    assert(addr != NULL);

    /* reset context */
    iasp_proto_ctx_init(&pctx);
    iasp_reset_message();

    /* receive with timeout */
    if(!iasp_proto_receive(addr, &pctx, NULL, IASP_SESSION_RECV_TIMEOUT)) {
        return SESSION_CMD_TIMEOUT;
    }
    sb = iasp_proto_get_payload_sb();

    debug_log("Received msg: %u bytes from ", sb->size);
    debug_print_address(&pctx.peer);
    debug_newline();
    debug_log("Received on ");
    debug_print_address(&pctx.addr);
    debug_newline();

    /* handle received message */
    return iasp_handle_message(&pctx, sb);
}


static void iasp_reset_message()
{
    memset(&msg, 0, sizeof(msg));
}


/* MESSAGE HANDLERS */
static iasp_session_result_t iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload)
{
    unsigned int msg_code;
    uint16_t lookup_code;
    const session_handler_lookup_t *lookup;
    iasp_session_t *s = NULL;

    /* get message code */
    if(!iasp_decode_varint(payload, &msg_code)) {
        return SESSION_CMD_INVALID_MSG;
    }

    /* check range */
    if(msg_code >= UINT8_MAX) {
        return SESSION_CMD_INVALID_MSG;
    }

    /* find handler */
    lookup_code = MSG_CODE(pctx->msg_type, msg_code);
    lookup = handlers[role];
    while(lookup->msg != 0) {
        if(lookup->msg == lookup_code) {
            break;
        }
        lookup++;
    }

    /* found handler */
    if(lookup->handler == NULL) {
        return SESSION_CMD_INVALID_MSG;
    }

    /* find session */
    {
        unsigned int i;

        for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
            iasp_proto_ctx_t *p;

            /* omit inactive sessions */
            if(sessions[i].active == false) {
                continue;
            }

            p = &sessions[i].pctx;

            /* match my address */
            if(!iasp_network_address_equal(&p->addr, &pctx->addr)) {
                continue;
            }

            /* match peer address */
            if(iasp_network_address_equal(&p->peer, &pctx->peer)) {
                s = &sessions[i];
                debug_log("Found session: %p\n", s);
                break;
            }
        }
    }

    /* create new session */
    if(s == NULL) {
        if(lookup_code != MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO)) {
            return SESSION_CMD_INVALID_MSG;
        }

        s = iasp_session_new(&pctx->addr, &pctx->peer);
        if(s == NULL) {
            return SESSION_CMD_NOMEM;
        }
    }

    /* handle message */
    if(lookup->handler(s, payload) == false) {
        return SESSION_CMD_ERROR;
    }

    return SESSION_CMD_OK;
}


static bool iasp_handler_init_hello(iasp_session_t * const s, streambuf_t *sb)
{
    streambuf_t *reply;
    iasp_identity_t *iid = NULL;
    iasp_session_side_data_t *i, *r;
    unsigned int j;

    /* decode message */
    if(!iasp_decode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        return false;
    }

    /* get side data */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* mark session side */
    s->side = SESSION_SIDE_RESPONDER;

    /* choose spn */
    s->spn = crypto_choose_spn(&msg.hmsg_init_hello.ids);
    if(s->spn == IASP_SPN_NONE) {
        return false;
    }

    /* save initiator ID */
    for(j = 0; j < msg.hmsg_init_hello.ids.id_count; ++j) {
        if(msg.hmsg_init_hello.ids.id[j].spn == s->spn) {
            iid = &msg.hmsg_init_hello.ids.id[j];
            break;
        }
    }
    if(iid == NULL) {
        return false;
    }
    memcpy(&i->id, iid, sizeof(iasp_identity_t));

    /* save initiator nonce */
    if(role != IASP_ROLE_CD) {
        memcpy(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t));
    }

    /* save peer's IDs for child session negotiation */
    if(role == IASP_ROLE_TP) {
        iasp_tpdata_set_ids(s->aux, &msg.hmsg_init_hello.ids);
    }

    /* prepare for reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();
    s->pctx.answer = true;

    /* set and save own ID */
    {
        iasp_identity_t *myid = role == IASP_ROLE_CD ? &msg.hmsg_redirect.id : &msg.hmsg_resp_hello.id;
        crypto_get_id(s->spn, myid);
        memcpy(&s->sides[SESSION_SIDE_RESPONDER].id, myid, sizeof(iasp_identity_t));
    }

    /* ================ ROLE DEPEND =================== */
    r->flags.byte = 0;
    if(role != IASP_ROLE_CD) {
        /* set session flags */
        if(!iasp_trust_is_trusted_peer(&i->id)) {
            r->flags.bits.send_hint = true;
        }

        /* add initiator NONCE */
        memcpy(&msg.hmsg_resp_hello.inonce, &i->nonce, sizeof(iasp_nonce_t));

        /* generate and set NONCE */
        {
            iasp_nonce_t *rn = &s->sides[SESSION_SIDE_RESPONDER].nonce;
            crypto_gen_nonce(rn);
            memcpy(&msg.hmsg_resp_hello.rnonce, rn, sizeof(iasp_nonce_t));
        }

        /* save flags */
        msg.hmsg_resp_hello.flags = r->flags;

        /* send responder hello */
        if(!iasp_encode_hmsg_resp_hello(reply, &msg.hmsg_resp_hello)) {
            abort();
        }
    }
    else {
        const iasp_address_t *tpaddr;

        /* add TP address and redirect */
        tpaddr = iasp_get_tpaddr();
        if(tpaddr == NULL) {
            return false;
        }

        /* deep copy (risk considered) */
        memcpy(&msg.hmsg_redirect.tp_address, tpaddr, sizeof(iasp_address_t));

        /* send redirect message */
        if(!iasp_encode_hmsg_redirect(sb, &msg.hmsg_redirect)) {
            abort();
        }
    }
    /* ================ ROLE DEPEND =================== */

    /* send reply */
    return iasp_proto_send(&s->pctx, reply);
}


static bool iasp_handler_resp_hello(iasp_session_t * const s, streambuf_t * const sb)
{
    uint8_t byte;
    streambuf_t *reply;
    iasp_session_side_data_t *i, *r;

    /* mark session side */
    s->side = SESSION_SIDE_INITIATOR;

    /* decode message */
    if(!iasp_decode_hmsg_resp_hello(sb, &msg.hmsg_resp_hello)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* check my nonce */
    if(memcmp(&i->nonce, &msg.hmsg_resp_hello, sizeof(iasp_nonce_t)) != 0) {
        debug_log("INONCE mismatch.\n");
        return false;
    }

    /* get SPN */
    s->spn = msg.hmsg_resp_hello.id.spn;

    /* get my ID */
    if(!crypto_get_id(s->spn, &i->id)) {
        return false;
    }

    /* get responder ID */
    memcpy(&r->id, &msg.hmsg_resp_hello.id, sizeof(iasp_identity_t));

    /* get responder NONCE */
    memcpy(&r->nonce, &msg.hmsg_resp_hello.rnonce, sizeof(iasp_nonce_t));

    /* get responder flags */
    r->flags = msg.hmsg_resp_hello.flags;

    /* prepare response */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* ================ ROLE DEPEND =================== */
    i->flags.byte = 0;
    if(role != IASP_ROLE_CD) {
        iasp_ffddata_t *ffd = (iasp_ffddata_t *)s->aux;

        /* set ephemeral key */
        msg.hmsg_init_auth.has_dhkey = true;
        crypto_ecdhe_genkey(s->spn, &msg.hmsg_init_auth.dhkey, &ffd->ecdhe_ctx);

        if(!iasp_trust_is_trusted_peer(&r->id)) {
            i->flags.bits.send_hint = true;
        }
    }
    else {
        if(!iasp_trust_is_trusted_tp(&r->id)) {
            i->flags.bits.oob_auth = true;
            i->flags.bits.send_pkey = true;
        }
    }
    msg.hmsg_init_auth.flags = i->flags;
    /* ================ ROLE DEPEND =================== */

    /* set hint if needed */
    if(r->flags.bits.send_hint) {
        msg.hmsg_init_auth.has_hint = true;
        if(!iasp_get_hint(&msg.hmsg_init_auth.hint)) {
            return false;
        }
    }

    /* set public key if needed */
    if(r->flags.bits.send_pkey) {
        msg.hmsg_init_auth.has_pkey = true;
        if(!crypto_get_pkey(s->spn, &msg.hmsg_init_auth.pkey)) {
            /* bad SPN - impossible to happen */
            abort();
        }
    }

    /* check if OOB key signature is needed */
    if(r->flags.bits.oob_auth) {
        msg.hmsg_init_auth.has_oobsig = true;

        /* signing */
        if(!crypto_sign_init(s->spn, IASP_SIG_HMAC)) {
            abort();
        }
        byte = (uint8_t)s->spn;
        crypto_sign_update(&byte, sizeof(byte));
        crypto_sign_update(i->id.data, sizeof(i->id.data));
        crypto_sign_update(r->id.data, sizeof(r->id.data));
        crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));

        /* add optional fields to signature */
        if(msg.hmsg_init_auth.has_dhkey) {
            crypto_sign_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
        }
        if(msg.hmsg_init_auth.has_hint) {
            crypto_sign_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
        }
        if(msg.hmsg_init_auth.has_pkey) {
            crypto_sign_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
        }

        /* finalize HMAC signature */
        msg.hmsg_init_auth.has_oobsig = true;
        if(!crypto_sign_final(&msg.hmsg_init_auth.oobsig)) {
            abort();
        }
    }

    /* set nonces */
    memcpy(&msg.hmsg_init_auth.inonce.data, i->nonce.data, sizeof(iasp_nonce_t));
    memcpy(&msg.hmsg_init_auth.rnonce.data, r->nonce.data, sizeof(iasp_nonce_t));

    /* sign everything */
    if(!crypto_sign_init(s->spn, IASP_SIG_EC)) {
        abort();
    }
    byte = (uint8_t)s->spn;
    crypto_sign_update(&byte, sizeof(byte));
    crypto_sign_update(i->id.data, sizeof(i->id.data));
    crypto_sign_update(r->id.data, sizeof(r->id.data));
    crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));

    /* add optional fields to signature */
    if(msg.hmsg_init_auth.has_dhkey) {
        crypto_sign_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
    }
    if(msg.hmsg_init_auth.has_hint) {
        crypto_sign_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
    }
    if(msg.hmsg_init_auth.has_pkey) {
        crypto_sign_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
    }
    if(msg.hmsg_init_auth.has_oobsig) {
        crypto_sign_update(msg.hmsg_init_auth.oobsig.sigdata, msg.hmsg_init_auth.oobsig.siglen);
    }

    /* finalize signature */
    if(!crypto_sign_final(&msg.hmsg_init_auth.sig)) {
        abort();
    }

    /* encode reply */
    if(!iasp_encode_hmsg_init_auth(reply, &msg.hmsg_init_auth)) {
       abort();
    }

    /* send response */
    return iasp_proto_send(&s->pctx, reply);
}


static bool iasp_handler_init_auth(iasp_session_t * const s, streambuf_t * const sb)
{
    uint8_t byte;
    streambuf_t *reply;
    iasp_tpdata_t *tpd = (iasp_tpdata_t *)s->aux;
    const iasp_pkey_t *pkey;
    iasp_session_side_data_t *i, *r;

    /* decode message */
    if(!iasp_decode_hmsg_init_auth(sb, &msg.hmsg_init_auth)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* check nonces */
    if(memcmp(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("INONCE mismatch.\n");
        return false;
    }
    if(memcmp(&r->nonce, &msg.hmsg_init_auth.rnonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("RNONCE mismatch.\n");
        return false;
    }

    /* set initiator flags */
    i->flags = msg.hmsg_init_auth.flags;

    /* set SPIs */
    memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
    memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));

    /* check hint if asked for */
    if(r->flags.bits.send_hint) {
        if(!msg.hmsg_init_auth.has_hint) {
            debug_log("HINT is missed.\n");
            return false;
        }

        /* TODO: do something with hint */
        debug_log("Hint: %.*s.\n", msg.hmsg_init_auth.hint.hintlen, (const char *)msg.hmsg_init_auth.hint.hintdata);
    }

    /* check pkey if asked for */
    if(r->flags.bits.send_pkey) {
        if(!msg.hmsg_init_auth.has_pkey) {
            debug_log("PKEY is missed.\n");
            return false;
        }

        /* TODO: do something with PKEY */
        debug_log("PKEY received.\n");
    }

    /* check OOB key signature if asked for */
    if(r->flags.bits.oob_auth) {
        if(!msg.hmsg_init_auth.has_oobsig) {
            debug_log("OOB key signature is missed.\n");
            return false;
        }

        /* sanity check */
        if(msg.hmsg_init_auth.oobsig.sigtype != IASP_SIG_HMAC) {
            debug_log("Invalid OOB signature.");
            return false;
        }

        /* check OOB signature */
        if(!crypto_verify_init(&i->id, IASP_SIG_HMAC)) {
            return false;
        }
        byte = (uint8_t)s->spn;
        crypto_verify_update(&byte, sizeof(byte));
        crypto_verify_update(i->id.data, sizeof(i->id.data));
        crypto_verify_update(r->id.data, sizeof(r->id.data));
        crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));

        /* check optional fields */
        if(msg.hmsg_init_auth.has_dhkey) {
            crypto_verify_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
        }
        if(msg.hmsg_init_auth.has_hint) {
            crypto_verify_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
        }
        if(msg.hmsg_init_auth.has_pkey) {
            crypto_verify_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
        }

        /* finalize verification */
        if(!crypto_verify_final(&msg.hmsg_init_auth.oobsig)) {
            debug_log("Peer's HMAC signature does not match!\n");
            return false;
        }

        debug_log("Peer's HMAC signature match!\n");
    }

    /* prepare data for signature verification */
    if(!crypto_verify_init(&i->id, IASP_SIG_EC)) {
        return false;
    }
    byte = (uint8_t)s->spn;
    crypto_verify_update(&byte, sizeof(byte));
    crypto_verify_update(i->id.data, sizeof(i->id.data));
    crypto_verify_update(r->id.data, sizeof(r->id.data));
    crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));

    /* choose key for ECDHE */
    if(!msg.hmsg_init_auth.has_dhkey) {
        /* find pkey by peer key id */
        pkey = crypto_get_pkey_by_id(&i->id);
        if(pkey == NULL) {
            return false;
        }
        debug_log("Using peer's public key for ECDHE\n");
    }
    else {
        pkey = &msg.hmsg_init_auth.dhkey;
        debug_log("Using received ephemeral key for ECDHE\n");
        crypto_verify_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
    }

    /* verify optional fields */
    if(msg.hmsg_init_auth.has_hint && r->flags.bits.send_hint) {
        crypto_verify_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
    }
    if(msg.hmsg_init_auth.has_pkey && r->flags.bits.send_pkey) {
        crypto_verify_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
    }
    if(msg.hmsg_init_auth.has_oobsig && r->flags.bits.oob_auth) {
        crypto_verify_update(msg.hmsg_init_auth.oobsig.sigdata, msg.hmsg_init_auth.oobsig.siglen);
    }

    /* verify signature */
    if(!crypto_verify_final(&msg.hmsg_init_auth.sig)) {
        debug_log("Peer's signature does not match!\n");
        return false;
    }
    debug_log("Peer's signature match!\n");

    /* generate ephemeral key */
    crypto_ecdhe_genkey(s->spn, NULL, &tpd->ffd.ecdhe_ctx);

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, pkey, &tpd->ffd.ecdhe_ctx)) {
        return false;
    }

    /* prepare reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* set nonces */
    memcpy(&msg.hmsg_resp_auth.inonce.data, i->nonce.data, sizeof(iasp_nonce_t));
    memcpy(&msg.hmsg_resp_auth.rnonce.data, r->nonce.data, sizeof(iasp_nonce_t));

    /* extract public part of ephemeral key */
    if(!crypto_ecdhe_pkey(&tpd->ffd.ecdhe_ctx, &msg.hmsg_resp_auth.dhkey)) {
        abort();
    }

    /* set hint if needed */
    if(i->flags.bits.send_hint) {
        msg.hmsg_resp_auth.has_hint = true;
        if(!iasp_get_hint(&msg.hmsg_resp_auth.hint)) {
            return false;
        }
    }

    /* set public key if needed */
    if(i->flags.bits.send_pkey) {
        msg.hmsg_resp_auth.has_pkey = true;
        if(!crypto_get_pkey(s->spn, &msg.hmsg_resp_auth.pkey)) {
            /* bad SPN - impossible to happen */
            abort();
        }
    }

    /* check if OOB key signature is needed */
    if(i->flags.bits.oob_auth) {
        msg.hmsg_resp_auth.has_oobsig = true;

        /* signing */
        if(!crypto_sign_init(s->spn, IASP_SIG_HMAC)) {
            abort();
        }
        byte = (uint8_t)s->spn;
        crypto_sign_update(&byte, sizeof(byte));
        crypto_sign_update(i->id.data, sizeof(i->id.data));
        crypto_sign_update(r->id.data, sizeof(r->id.data));
        crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));
        crypto_sign_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

        /* add optional fields to signature */
        if(msg.hmsg_resp_auth.has_hint) {
            crypto_sign_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
        }
        if(msg.hmsg_resp_auth.has_pkey) {
            crypto_sign_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
        }

        /* finalize HMAC signature */
        msg.hmsg_resp_auth.has_oobsig = true;
        if(!crypto_sign_final(&msg.hmsg_resp_auth.oobsig)) {
            abort();
        }
    }

    /* sign negotiation */
    if(!crypto_sign_init(s->spn, IASP_SIG_EC)) {
        abort();
    }
    byte = (uint8_t)s->spn;
    crypto_sign_update(&byte, sizeof(byte));
    crypto_sign_update(i->id.data, sizeof(i->id.data));
    crypto_sign_update(r->id.data, sizeof(r->id.data));
    crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));
    crypto_sign_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

    /* add optional fields to signature */
    if(msg.hmsg_resp_auth.has_hint) {
        crypto_sign_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
    }
    if(msg.hmsg_resp_auth.has_pkey) {
        crypto_sign_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
    }
    if(msg.hmsg_resp_auth.has_oobsig) {
        crypto_sign_update(msg.hmsg_resp_auth.oobsig.sigdata, msg.hmsg_resp_auth.oobsig.siglen);
    }

    /* finalize signature */
    if(!crypto_sign_final(&msg.hmsg_resp_auth.sig)) {
        abort();
    }

    /* encode reply */
    if(!iasp_encode_hmsg_resp_auth(reply, &msg.hmsg_resp_auth)) {
        return false;
    }

    /* event callback */
    if(event_cb != NULL) {
        event_cb(s, SESSION_EVENT_ESTABLISHED);
    }

    /* send reply */
    return iasp_proto_send(&s->pctx, reply);
}


static bool iasp_handler_resp_auth(iasp_session_t * const s, streambuf_t * const sb)
{
    uint8_t byte;
    iasp_session_side_data_t *i, *r;
    crypto_ecdhe_context_t *ecdhe_ctx = NULL;

    /* decode message */
    if(!iasp_decode_hmsg_resp_auth(sb, &msg.hmsg_resp_auth)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* check nonces */
    if(memcmp(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("INONCE mismatch.\n");
        return false;
    }
    if(memcmp(&r->nonce, &msg.hmsg_init_auth.rnonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("RNONCE mismatch.\n");
        return false;
    }

    /* check hint if asked for */
    if(i->flags.bits.send_hint) {
        if(!msg.hmsg_resp_auth.has_hint) {
            debug_log("HINT is missed.\n");
            return false;
        }

        /* TODO: do something with hint */
        debug_log("Hint: %.*s.\n", msg.hmsg_resp_auth.hint.hintlen, (const char *)msg.hmsg_resp_auth.hint.hintdata);
    }

    /* check pkey if asked for */
    if(i->flags.bits.send_pkey) {
        if(!msg.hmsg_resp_auth.has_pkey) {
            debug_log("PKEY is missed.\n");
            return false;
        }

        /* TODO: do something with PKEY */
        debug_log("PKEY received.\n");
    }

    /* check OOB key signature if asked for */
    if(i->flags.bits.oob_auth) {
        if(!msg.hmsg_resp_auth.has_oobsig) {
            debug_log("OOB key signature is missed.\n");
            return false;
        }

        /* sanity check */
        if(msg.hmsg_resp_auth.oobsig.sigtype != IASP_SIG_HMAC) {
            debug_log("Invalid OOB signature.\n");
            return false;
        }

        /* check OOB signature */
        if(!crypto_verify_init(&i->id, IASP_SIG_HMAC)) {
            return false;
        }
        byte = (uint8_t)s->spn;
        crypto_verify_update(&byte, sizeof(byte));
        crypto_verify_update(i->id.data, sizeof(i->id.data));
        crypto_verify_update(r->id.data, sizeof(r->id.data));
        crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));
        crypto_verify_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

        /* check optional fields */
        if(msg.hmsg_resp_auth.has_hint) {
            crypto_verify_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
        }
        if(msg.hmsg_resp_auth.has_pkey) {
            crypto_verify_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
        }

        /* finalize verification */
        if(!crypto_verify_final(&msg.hmsg_resp_auth.oobsig)) {
            debug_log("Peer's HMAC signature does not match!\n");
            return false;
        }

        debug_log("Peer's HMAC signature match!\n");
    }

    /* verify signature */
    if(!crypto_verify_init(&r->id, s->peer_auth_meth)) {
        return false;
    }
    byte = (uint8_t)s->spn;
    crypto_verify_update(&byte, sizeof(byte));
    crypto_verify_update(i->id.data, sizeof(i->id.data));
    crypto_verify_update(r->id.data, sizeof(r->id.data));
    crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));
    crypto_verify_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

    /* add optional fields to signature */
    if(msg.hmsg_resp_auth.has_hint) {
        crypto_verify_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
    }
    if(msg.hmsg_resp_auth.has_pkey) {
        crypto_verify_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
    }
    if(msg.hmsg_resp_auth.has_oobsig) {
        crypto_verify_update(msg.hmsg_resp_auth.oobsig.sigdata, msg.hmsg_resp_auth.oobsig.siglen);
    }

    /* finalize verification */
    if(!crypto_verify_final(&msg.hmsg_resp_auth.sig)) {
        debug_log("Peer's signature does not match!\n");
        return false;
    }
    debug_log("Peer's signature match!\n");

    /* set SPis */
    memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
    memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));

    /* get ephemeral key if possible */
    if(role != IASP_ROLE_CD) {
        iasp_tpdata_t *tpd = s->aux;
        ecdhe_ctx = &tpd->ffd.ecdhe_ctx;
    }

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, &msg.hmsg_resp_auth.dhkey, ecdhe_ctx)) {
        return false;
    }

    /* event callback */
    if(event_cb != NULL) {
        event_cb(s, SESSION_EVENT_ESTABLISHED);
    }

    return true;
}


static bool iasp_session_generate_secret(iasp_session_t *s, const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx)
{
    static uint8_t buffer[IASP_MAX_KEY_SIZE*2 + sizeof(iasp_salt_t)];
    static uint8_t saltbuffer[sizeof(iasp_spi_t) * 2];
    binbuf_t saltbb;
    size_t keysize = crypto_get_key_size(pkey->spn);
    size_t gensize = 2*keysize + sizeof(iasp_salt_t);
    iasp_session_side_data_t *i, *r;

    assert(gensize <= sizeof(buffer));

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* prepare salt buffer */
    memcpy(saltbuffer, i->spi.spidata, sizeof(iasp_spi_t));
    memcpy(saltbuffer + sizeof(iasp_spi_t), r->spi.spidata, sizeof(iasp_spi_t));
    saltbb.buf = saltbuffer;
    saltbb.size = sizeof(saltbuffer);

    /* complete ECDHE */
    if(!crypto_ecdhe_compute_secret(pkey, ecdhe_ctx, buffer, gensize, &saltbb)) {
        return false;
    }
    debug_log("Shared secret computed: ");
    debug_print_binary(buffer, gensize);
    debug_newline();

    /* distribute material */
    memcpy(i->key.keydata, buffer, keysize);
    memcpy(r->key.keydata, buffer + keysize, keysize);
    memcpy(s->salt.saltdata, buffer + 2*keysize, sizeof(iasp_salt_t));

    /* key information */
    i->key.keysize = r->key.keysize = keysize;
    i->key.spn = r->key.spn = pkey->spn;

    return true;
}


static bool iasp_handler_redirect(iasp_session_t * const s, streambuf_t * const sb)
{
    iasp_session_side_data_t *i, *r;
    iasp_session_t *redirect;

    /* decode message */
    if(!iasp_decode_hmsg_redirect(sb, &msg.hmsg_redirect)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* event callback */
    if(event_cb != NULL) {
        event_cb(s, SESSION_EVENT_REDIRECT);
    }

    /* set SPN */
    s->spn = msg.hmsg_redirect.id.spn;

    /* get my ID */
    if(!crypto_get_id(s->spn, &i->id)) {
        return false;
    }

    /* copy peers ID */
    memcpy(&r->id, &msg.hmsg_redirect.id, sizeof(iasp_identity_t));

    /* find session for obtained redirection */
    if((redirect = iasp_session_by_peer(&msg.hmsg_redirect.tp_address)) == NULL) {
        /* establish new session if there is no previously established */
        debug_log("Cannot find session for redirect address.\n");
        /* discard const qualifier for private usage */
        s->redirect = (iasp_session_t *)iasp_session_start(&s->pctx.addr, &msg.hmsg_redirect.tp_address);
        if(s->redirect == NULL) {
            debug_log("Cannot create redirect session.\n");
            return false;
        }
    }
    else {
        streambuf_t *keyreq;
        iasp_mgmt_req_session_t *m = &msg.mgmt_req;

        /* save redirection */
        s->redirect = redirect;

        /* prepare for key request */
        iasp_reset_message();
        iasp_proto_reset_payload();
        keyreq = iasp_proto_get_payload_sb();

        /* add peer address */
        memcpy(&m->peer_address, &s->pctx.peer, sizeof(iasp_address_t));

        /* check if my address is needed */
        if(!iasp_network_address_equal(&s->pctx.addr, &s->redirect->pctx.addr)) {
            m->has_my_address = true;
            memcpy(&m->my_address, &s->pctx.addr, sizeof(iasp_address_t));
        }

        /* generate SPI from previously generated NONCE */
        memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
        memcpy(&m->spi, &i->spi, sizeof(iasp_spi_t));

        /* send key request */
        s->redirect->pctx.answer = false;
        s->redirect->pctx.msg_type = IASP_MSG_MGMT;
        return iasp_encode_mgmt_req_session(keyreq, m) && iasp_proto_send(&s->redirect->pctx, keyreq);
    }

    return true;
}


static iasp_session_t *iasp_session_by_peer(const iasp_address_t * const peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        iasp_session_t *s = &sessions[i];

        /* skip inactive sessions */
        if(!s->active) {
            continue;
        }

        /* check peer address */
        if(iasp_network_address_equal(&s->pctx.peer, peer)) {
            return s;
        }
    }

    /* nothing found */
    return NULL;
}


static iasp_session_t *iasp_session_by_peer_ip(const iasp_address_t * const peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        iasp_session_t *s = &sessions[i];

        /* skip inactive sessions */
        if(!s->active) {
            continue;
        }

        /* compare IP addresses */
        if(memcmp(iasp_network_address_ip(&s->pctx.peer), iasp_network_address_ip(peer), sizeof(iasp_ip_t)) == 0) {
            return s;
        }
    }

    /* nothing found */
    return NULL;
}


static bool iasp_handler_mgmt_req(iasp_session_t * const s, streambuf_t * const sb)
{
    iasp_session_t *session_responder;
    iasp_tpdata_t *tpdi, *tpdr;
    iasp_spn_code_t spn;
    //iasp_key_t key;

    /* assert TP role */
    assert(role == IASP_ROLE_TP);

    /* decode message */
    if(!iasp_decode_mgmt_req_session(sb, &msg.mgmt_req)) {
        debug_log("Cannot decode session request message.\n");
        return false;
    }

    /* find session for peer */
    session_responder = iasp_session_by_peer_ip(&msg.mgmt_req.peer_address);
    if(session_responder == NULL) {
        /* TODO: repond with error */
        debug_log("Cannot find responder session.\n");
        return false;
    }

    /* extract TP data */
    tpdi = (iasp_tpdata_t *)s->aux;
    tpdr = (iasp_tpdata_t *)session_responder->aux;

    /* choose SPN for session */
    spn = crypto_choose_spn2(&tpdi->ids, &tpdr->ids);
    if(spn == IASP_SPN_NONE || spn == IASP_SPN_MAX) {
        /* TODO: error */
        debug_log("Cannot find matching SPN for child session.\n");
        return false;
    }
    debug_log("SPN for child session chosen: ");
    debug_print_spn(spn);
    debug_newline();

#if 0
    /* generate key material */
    crypto_gen_key(msg.mgmt_req. &key);
#endif

    return true;
}
