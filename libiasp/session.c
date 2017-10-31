#include "session.h"

#include "crypto.h"
#include "encode.h"
#include "streambuf.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


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

    /* prepare headers */
    this->pctx.msg_type = IASP_MSG_HANDSHAKE;

    /* get payload space */
    iasp_proto_reset_payload();
    sb = iasp_proto_get_payload_sb();

    /* encode hello message */
    if(!iasp_encode_hmsg_init_hello(sb, crypto_get_supported_spns())) {
        abort();
    }

    /* proto send message */
    if(!iasp_proto_send(&this->pctx, NULL)) {
        abort();
    }
}

