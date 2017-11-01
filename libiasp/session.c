#include "session.h"

#include "crypto.h"
#include "encode.h"
#include "decode.h"
#include "streambuf.h"
#include "types.h"

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


/* message handlers */
static bool iasp_handler_init_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_hello(iasp_session_t * const, streambuf_t * const);


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
        {0, NULL},
};

/* FFD handlers */
static const session_handler_lookup_t ffd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {0, NULL},
};

/* TP handlers */
static const session_handler_lookup_t tp_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
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
            sessions[i].active = true;

            iasp_proto_ctx_init(&sessions[i].pctx);
            sessions[i].pctx.addr = addr;
            sessions[i].pctx.peer = peer;

            return &sessions[i];
        }
    }

    return NULL;
}


void iasp_session_init(iasp_session_t * const this, const iasp_address_t *addr, const iasp_address_t *peer_addr)
{
    assert(addr != NULL);
    assert(peer_addr != NULL);

    memset(this, 0, sizeof(iasp_session_t));

    iasp_proto_ctx_init(&this->pctx);
    this->pctx.addr = addr;
    this->pctx.peer = peer_addr;
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
    iasp_session_handle_addr(s->pctx.addr);
}


void iasp_session_respond(iasp_session_t * const this)
{
    /* TODO: implement */
}


void iasp_session_handle_addr(const iasp_address_t * const addr)
{
    iasp_proto_ctx_t pctx;
    iasp_address_t peer_addr = {NULL};
    streambuf_t *sb;

    assert(addr != NULL);

    /* TODO: set timeout */
    if(!iasp_proto_receive(addr, &peer_addr, &pctx, NULL, 5000)) {
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
            if(!iasp_network_address_equal(p->addr, pctx->addr)) {
                continue;
            }

            /* match peer address */
            if(iasp_network_address_equal(p->peer, pctx->peer)) {
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
        s = iasp_session_new(pctx->addr, pctx->peer);
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
    iasp_spn_code_t spn;

    /* decode message */
    if(!iasp_decode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        return false;
    }

    /* choose spn */
    spn = crypto_choose_spn(&msg.hmsg_init_hello.ids);
    if(spn == IASP_SPN_NONE) {
        return false;
    }

    /* prepare for reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* set ID */
    crypto_get_id(spn, &msg.hmsg_resp_hello.id);

    /* generate and set NONCE */
    crypto_gen_nonce(&s->rnonce);
    memcpy(&msg.hmsg_resp_hello.rnonce, &s->rnonce, sizeof(iasp_nonce_t));

    /* send responder hello */
    s->pctx.answer = true;
    return iasp_encode_hmsg_resp_hello(reply, &msg.hmsg_resp_hello) &&
            iasp_proto_send(&s->pctx, reply);
}


static bool iasp_handler_resp_hello(iasp_session_t * const s, streambuf_t * const sb)
{
    /* decode message */
    if(!iasp_decode_hmsg_resp_hello(sb, &msg.hmsg_resp_hello)) {
        return false;
    }

    return true;
}
