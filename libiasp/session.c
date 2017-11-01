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
typedef bool (*iasp_session_handler_t)(iasp_session_t * const);

/* rx/tx message structure */
static iasp_msg_storage_t msg;
static iasp_role_t role;

/* private methods */
static void iasp_reset_message(void);
static void iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload);


/* message handlers */
static bool iasp_handler_init_hello(iasp_session_t * const);


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
        {0, NULL},
};

/* FFD handlers */
static const session_handler_lookup_t ffd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {0, NULL},
};

/* TP handlers */
static const session_handler_lookup_t tp_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {0, NULL},
};

const session_handler_lookup_t *handlers[IASP_ROLE_MAX] =
{
        cd_session_handlers, ffd_session_handlers, tp_session_handlers
};


void iasp_session_set_role(iasp_role_t r)
{
    assert(role < IASP_ROLE_MAX);
    role = r;
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


void iasp_session_start(iasp_session_t * const this)
{
    streambuf_t *sb;

    assert(this != NULL);

    /* prepare headers */
    this->pctx.msg_type = IASP_MSG_HANDSHAKE;

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
    if(!iasp_proto_send(&this->pctx, NULL)) {
        abort();
    }
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

    if(!iasp_proto_receive(addr, &peer_addr, &pctx, NULL)) {
        abort();
    }

    iasp_reset_message();
    sb = iasp_proto_get_payload_sb();
    iasp_handle_message(&pctx, sb);

    {
        iasp_handshake_msg_code_t msg_code;

        if(!iasp_decode_hmsg_code(sb, &msg_code)) {
            abort();
        }

        if(msg_code != IASP_HMSG_INIT_HELLO) {
            abort();
        }

        if(!iasp_decode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
            abort();
        }
    }

    iasp_reset_message();
    iasp_proto_reset_payload();
    sb = iasp_proto_get_payload_sb();

    {


    }
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
    }

    /* found handler */
    if(lookup->handler == NULL) {
        abort();
    }

    /* TODO: find session */

    /* handle message */
    lookup->handler(NULL);
}


static bool iasp_handler_init_hello(iasp_session_t * const s)
{
    return true;
}
