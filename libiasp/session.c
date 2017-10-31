#include "session.h"

#include "crypto.h"
#include "encode.h"
#include "decode.h"
#include "streambuf.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


static iasp_msg_storage_t msg;

static void iasp_reset_message(void);


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

    sb = iasp_proto_get_payload_sb();
    iasp_reset_message();
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
}


static void iasp_reset_message()
{
    memset(&msg, 0, sizeof(msg));
}
