#include "proto.h"
#include "network.h"
#include "streambuf.h"
#include "binbuf.h"
#include "types.h"

#include <assert.h>
#include <stdbool.h>


#define IASP_PROTO_BUFFER_SIZE (256)
static uint8_t buffer[IASP_PROTO_BUFFER_SIZE];


static bool iasp_proto_send_common(iasp_proto_ctx_t * const this, streambuf_t * const payload, bool answer);


void iasp_proto_put_outer_hdr(uint8_t *buf, bool encrypted, iasp_pv_t pv, iasp_spn_code_t spn)
{
    iasp_outer_header_t oh;

    assert(pv < IASP_PV_MAX);
    assert(spn < IASP_SPN_MAX);

    oh.bits.e = encrypted;
    oh.bits.pv = pv;
    oh.bits.spn = spn;

    *buf = oh.byte;
}


void iasp_proto_put_inner_hdr(uint8_t *buf, iasp_msg_type_t msg_type, bool answer, uint8_t pn)
{
    iasp_inner_hdr_t ih;

    assert(msg_type < IASP_MSG_MAX);
    assert(pn < IASP_PROTO_PN_MAX);

    ih.bits.r = 0;
    ih.bits.mt = msg_type;
    ih.bits.a = answer;
    ih.bits.pn = pn;

    *buf = ih.byte;
}


/* TODO: send without rewriting payload */
bool iasp_proto_send(iasp_proto_ctx_t * const this, streambuf_t * const payload)
{
    return iasp_proto_send_common(this, payload, false);
}


bool iasp_proto_send_answer(iasp_proto_ctx_t * const this, streambuf_t * const payload)
{

    return iasp_proto_send_common(this, payload, true);
}


static bool iasp_proto_send_common(iasp_proto_ctx_t * const this, streambuf_t * const payload, bool answer)
{
    uint8_t oh, ih;
    streambuf_t sb;
    uint8_t pn = this->pn;

    streambuf_init(&sb, buffer, 0, IASP_PROTO_BUFFER_SIZE);

    /* increment packet number if it is not an answer */
    if(!answer) {
        pn++;
    }

    /* prepare headers */
    iasp_proto_put_outer_hdr(&oh, this->encrypted, this->pv, this->spn);
    iasp_proto_put_inner_hdr(&ih, this->msg_type, answer, pn);

    /* put headers */
    if(!streambuf_write(&sb, &oh, sizeof(oh)) || streambuf_write(&sb, &ih, sizeof(ih))) {
        return false;
    }

    /* put payload */
    if(!streambuf_write_sb(&sb, payload)) {
        return false;
    }

    /* send packet */
    if(!iasp_network_send(this->addr, this->peer, streambuf_to_bb(&sb))) {
        return false;
    }

    this->pn = pn;

    return true;
}
