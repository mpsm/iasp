#include "session.h"

#include "crypto.h"
#include "encode.h"
#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "tp.h"
#include "debug.h"

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

    /* encode hello message */
    iasp_reset_message();
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


void iasp_session_handle_addr(const iasp_address_t * const addr)
{
    iasp_proto_ctx_t pctx;
    streambuf_t *sb;

    assert(addr != NULL);

    /* TODO: set proper timeout */
    iasp_proto_ctx_init(&pctx);
    if(!iasp_proto_receive(addr, &pctx, NULL, 50000)) {
        abort();
    }

    iasp_reset_message();
    sb = iasp_proto_get_payload_sb();
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
                break;
            }
        }
    }

    /* create new session */
    if(s == NULL) {
        if(lookup_code != MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO)) {
            abort();
        }
        /* TODO: dup peer address */
        s = iasp_session_new(&pctx->addr, &pctx->peer);
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
    unsigned int i;

    /* decode message */
    if(!iasp_decode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        return false;
    }

    /* mark session side */
    s->side = SESSION_SIDE_RESPONDER;

    /* choose spn */
    s->spn = crypto_choose_spn(&msg.hmsg_init_hello.ids);
    if(s->spn == IASP_SPN_NONE) {
        return false;
    }

    /* save initiator ID */
    for(i = 0; i < msg.hmsg_init_hello.ids.id_count; ++i) {
        if(msg.hmsg_init_hello.ids.id[i].spn == s->spn) {
            iid = &msg.hmsg_init_hello.ids.id[i];
            break;
        }
    }
    if(iid == NULL) {
        return false;
    }
    memcpy(&s->sides[SESSION_SIDE_INITIATOR].id, iid, sizeof(iasp_identity_t));

    /* prepare for reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* set and save own ID */
    crypto_get_id(s->spn, &msg.hmsg_resp_hello.id);
    memcpy(&s->sides[SESSION_SIDE_RESPONDER].id, &msg.hmsg_resp_hello.id, sizeof(iasp_identity_t));

    /* generate and set NONCE */
    {
        iasp_nonce_t *rn = &s->sides[SESSION_SIDE_RESPONDER].nonce;
        crypto_gen_nonce(rn);
        memcpy(&msg.hmsg_resp_hello.rnonce, rn, sizeof(iasp_nonce_t));
    }

    /* allocate TP data for future use */
    if(role != IASP_ROLE_CD) {
        iasp_tpdata_t *tpd = NULL;

        iasp_tpdata_init(&tpd);
        s->aux = tpd;
    }

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

    /* generate NONCE */
    crypto_gen_nonce(&i->nonce);

    /* signing */
    if(!crypto_sign_init(s->spn)) {
        abort();
    }
    byte = (uint8_t)s->spn;
    crypto_sign_update(&byte, sizeof(byte));
    crypto_sign_update(i->id.data, sizeof(i->id.data));
    crypto_sign_update(r->id.data, sizeof(r->id.data));
    crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));

    /* prepare response */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    if(role != IASP_ROLE_CD) {
        iasp_tpdata_t *tpd = NULL;

        /* allocate TP data for future use */
        iasp_tpdata_init(&tpd);
        s->aux = tpd;

        /* set ephemeral key */
        msg.hmsg_init_auth.has_pkey = true;
        crypto_ecdhe_genkey(s->spn, &msg.hmsg_init_auth.pkey, &tpd->ecdhe_ctx);

        /* add key to signature */
        crypto_sign_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
    }

    /* set nonces */
    memcpy(&msg.hmsg_init_auth.inonce.data, i->nonce.data, sizeof(iasp_nonce_t));
    memcpy(&msg.hmsg_init_auth.rnonce.data, r->nonce.data, sizeof(iasp_nonce_t));

    /* set signature */
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

    /* get initiator nonce, check own nonce */
    memcpy(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t));
    if(memcmp(&r->nonce, &msg.hmsg_init_auth.rnonce, sizeof(iasp_nonce_t)) != 0) {
        return false;
    }

    /* prepare data for signature verification */
    if(!crypto_verify_init(&i->id)) {
        return false;
    }
    byte = (uint8_t)s->spn;
    crypto_verify_update(&byte, sizeof(byte));
    crypto_verify_update(i->id.data, sizeof(i->id.data));
    crypto_verify_update(r->id.data, sizeof(r->id.data));
    crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));

    /* choose key for ECDHE */
    if(!msg.hmsg_init_auth.has_pkey) {
        /* find pkey by peer key id */
        pkey = crypto_get_pkey_by_id(&i->id);
        if(pkey == NULL) {
            return false;
        }
        debug_log("Using peer's public key for ECDHE\n");
    }
    else {
        pkey = &msg.hmsg_init_auth.pkey;
        debug_log("Using received ephemeral key for ECDHE\n");
        crypto_verify_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
    }

    /* verify signature */
    if(!crypto_verify_final(&msg.hmsg_init_auth.sig)) {
        debug_log("Peer's signature does not match!\n");
        return false;
    }
    debug_log("Peer's signature match!\n");

    /* prepare reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* generate ephemeral key */
    crypto_ecdhe_genkey(s->spn, &msg.hmsg_resp_auth.pkey, &tpd->ecdhe_ctx);

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, pkey, &tpd->ecdhe_ctx)) {
        return false;
    }

    /* set SPis */
    memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
    memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));

    /* sign negotiation */
    msg.hmsg_resp_auth.has_hmac = false;
    if(!crypto_sign_init(s->spn)) {
        abort();
    }
    crypto_sign_update(&byte, sizeof(byte));
    crypto_sign_update(i->id.data, sizeof(i->id.data));
    crypto_sign_update(r->id.data, sizeof(r->id.data));
    crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_sign_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
    crypto_sign_final(&msg.hmsg_resp_auth.sig.ecsig);

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

    /* decode message */
    if(!iasp_decode_hmsg_resp_auth(sb, &msg.hmsg_resp_auth)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* verify signature */
    if(!crypto_verify_init(&r->id)) {
        return false;
    }
    byte = (uint8_t)s->spn;
    crypto_verify_update(&byte, sizeof(byte));
    crypto_verify_update(i->id.data, sizeof(i->id.data));
    crypto_verify_update(r->id.data, sizeof(r->id.data));
    crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_verify_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
    if(!crypto_verify_final(&msg.hmsg_resp_auth.sig.ecsig)) {
        debug_log("Peer's signature does not match!\n");
        return false;
    }
    debug_log("Peer's signature match!\n");

    /* set SPis */
    memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
    memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, &msg.hmsg_resp_auth.pkey, NULL)) {
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

