#include "session.h"

#include "iasp.h"
#include "crypto.h"
#include "encode.h"
#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "tp.h"
#include "debug.h"
#include "trust.h"
#include "role.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


/* session handler */
typedef bool (*iasp_session_handler_t)(iasp_session_t * const, streambuf_t * const);

/* session data */
static iasp_session_t sessions[IASP_CONFIG_MAX_SESSIONS];

/* rx/tx message structure */
static iasp_msg_storage_t msg;
static iasp_role_t role;

/* private methods */
static void iasp_reset_message(void);
static void iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload);
static bool iasp_session_generate_secret(iasp_session_t *s, const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx);;


/* message handlers */
static bool iasp_handler_init_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_init_auth(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_auth(iasp_session_t * const, streambuf_t * const);


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
        {0, NULL},
};

/* FFD handlers */
static const session_handler_lookup_t ffd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {0, NULL},
};

/* TP handlers */
static const session_handler_lookup_t tp_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {0, NULL},
};

const session_handler_lookup_t *handlers[IASP_ROLE_MAX] =
{
        cd_session_handlers, ffd_session_handlers, tp_session_handlers
};


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
            iasp_session_init(s, addr, peer);
            return s;
        }
    }

    return NULL;
}


void iasp_session_init(iasp_session_t * const this, const iasp_address_t *addr, const iasp_address_t *peer_addr)
{
    assert(addr != NULL);
    assert(peer_addr != NULL);

    memset(this, 0, sizeof(iasp_session_t));

    this->active = true;
    iasp_proto_ctx_init(&this->pctx);
    iasp_network_address_dup(addr, &this->pctx.addr);
    iasp_network_address_dup(peer_addr, &this->pctx.peer);
}


void iasp_session_start(const iasp_address_t *addr, const iasp_address_t *peer)
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
        abort();
    }

    /* handle response */
    iasp_session_handle_addr(&s->pctx.addr);

    /* handle second response */
    iasp_session_handle_addr(&s->pctx.addr);
}


void iasp_session_respond(iasp_session_t * const this)
{
    /* TODO: implement */
}


void iasp_session_handle_any()
{
    iasp_address_t addr = { NULL };

    iasp_session_handle_addr(&addr);
}


void iasp_session_handle_addr(iasp_address_t * const addr)
{
    iasp_proto_ctx_t pctx;
    streambuf_t *sb;

    assert(addr != NULL);

    /* reset context */
    iasp_proto_ctx_init(&pctx);
    iasp_reset_message();

    /* TODO: set proper timeout */
    if(!iasp_proto_receive(addr, &pctx, NULL, 50000)) {
        abort();
    }
    sb = iasp_proto_get_payload_sb();

    debug_log("Received msg: %u bytes from ", sb->size);
    debug_print_address(&pctx.peer);
    debug_newline();
    debug_log("Received on ");
    debug_print_address(&pctx.addr);
    debug_newline();

    /* handle received message */
    iasp_handle_message(&pctx, sb);
}


static void iasp_reset_message()
{
    memset(&msg, 0, sizeof(msg));
}


/* MESSAGE HANDLERS */
static void iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload)
{
    unsigned int msg_code;
    uint16_t lookup_code;
    const session_handler_lookup_t *lookup;
    iasp_session_t *s = NULL;

    /* get message code */
    if(!iasp_decode_varint(payload, &msg_code)) {
        abort();
    }

    /* check range */
    if(msg_code >= UINT8_MAX) {
        abort();
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
        abort();
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
            abort();
        }

        s = iasp_session_new(&pctx->addr, &pctx->peer);
        debug_log("Created new session: %p\n", s);
        if(s == NULL) {
            abort();
        }
    }

    /* handle message */
    if(lookup->handler(s, payload) == false) {
        abort();
    }
}


static bool iasp_handler_init_hello(iasp_session_t * const s, streambuf_t *sb)
{
    streambuf_t *reply;
    iasp_identity_t *iid = NULL;
    iasp_session_side_data_t *i;
    unsigned int j;

    /* decode message */
    if(!iasp_decode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        return false;
    }

    /* get side data */
    i = &s->sides[SESSION_SIDE_INITIATOR];

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
    memcpy(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t));

    /* prepare for reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* set and save own ID */
    crypto_get_id(s->spn, &msg.hmsg_resp_hello.id);
    memcpy(&s->sides[SESSION_SIDE_RESPONDER].id, &msg.hmsg_resp_hello.id, sizeof(iasp_identity_t));

    /* add initiator NONCE */
    memcpy(&msg.hmsg_resp_hello.inonce, &i->nonce, sizeof(iasp_nonce_t));

    /* generate and set NONCE */
    {
        iasp_nonce_t *rn = &s->sides[SESSION_SIDE_RESPONDER].nonce;
        crypto_gen_nonce(rn);
        memcpy(&msg.hmsg_resp_hello.rnonce, rn, sizeof(iasp_nonce_t));
    }

    /* ================ ROLE DEPEND =================== */
    if(role != IASP_ROLE_CD) {
        iasp_tpdata_t *tpd = NULL;

        /* allocate TP data for future use */
        iasp_tpdata_init(&tpd);
        s->aux = tpd;

        /* set session flags */
        s->flags.byte = 0;
        if(!iasp_trust_is_trusted_peer(&i->id)) {
            s->flags.bits.send_hint = true;
        }
        msg.hmsg_resp_hello.flags.byte = s->flags.byte;
    }
    /* ================ ROLE DEPEND =================== */

    /* send responder hello */
    s->pctx.answer = true;
    return iasp_encode_hmsg_resp_hello(reply, &msg.hmsg_resp_hello) &&
            iasp_proto_send(&s->pctx, reply);
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
        iasp_tpdata_t *tpd = NULL;

        /* allocate TP data for future use */
        iasp_tpdata_init(&tpd);
        s->aux = tpd;

        /* set ephemeral key */
        msg.hmsg_init_auth.has_dhkey = true;
        crypto_ecdhe_genkey(s->spn, &msg.hmsg_init_auth.dhkey, &tpd->ecdhe_ctx);

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
    crypto_ecdhe_genkey(s->spn, NULL, &tpd->ecdhe_ctx);

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, pkey, &tpd->ecdhe_ctx)) {
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
    if(!crypto_ecdhe_pkey(&tpd->ecdhe_ctx, &msg.hmsg_resp_auth.dhkey)) {
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
    crypto_verify_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);

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
        ecdhe_ctx = &tpd->ecdhe_ctx;
    }

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, &msg.hmsg_resp_auth.pkey, ecdhe_ctx)) {
        return false;
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

