#include "proto.h"
#include "network.h"
#include "streambuf.h"
#include "binbuf.h"
#include "types.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/* private fields */
size_t bufsize;
uint8_t *buf;
streambuf_t packet_sb;
streambuf_t payload_sb;


/* private methods */
static bool iasp_proto_send_common(iasp_proto_ctx_t * const this, streambuf_t * const payload, bool answer);
static void iasp_reset_packet(bool encrypted);


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
    uint8_t pn = this->pn;
    binbuf_t bb;

    /* prepare packet sb */
    iasp_reset_packet(this->encrypted);

    /* increment packet number if it is not an answer */
    if(!answer) {
        pn++;
    }

    /* prepare headers */
    iasp_proto_put_outer_hdr(&oh, this->encrypted, this->pv, this->spn);
    iasp_proto_put_inner_hdr(&ih, this->msg_type, answer, pn);

    /* put headers */
    if(!streambuf_write(&packet_sb, &oh, sizeof(oh)) || streambuf_write(&packet_sb, &ih, sizeof(ih))) {
        return false;
    }

    /* prepare descriptor */
    bb.buf = packet_sb.data;
    bb.size = packet_sb.size;
    if(payload != NULL) {
        if(!streambuf_write_sb(&packet_sb, payload)) {
            return false;
        }
        bb.size = packet_sb.size;
    }
    else {
        bb.size = packet_sb.size + payload_sb.size;
    }

    /* send packet */
    if(!iasp_network_send(this->addr, this->peer, &bb)) {
        return false;
    }

    this->pn = pn;

    return true;
}


void iasp_proto_init(uint8_t * obuf, size_t obuflen)
{
    assert(obuflen > 0);
    assert(buf != NULL);

    buf = obuf;
    bufsize = obuflen;

    iasp_proto_reset_payload();
}


streambuf_t * iasp_proto_get_payload_sb()
{
    return &payload_sb;
}


void iasp_proto_reset_payload()
{
    streambuf_init(&payload_sb, buf + IASP_PROTO_MAX_HEADERS_SIZE, 0, bufsize - IASP_PROTO_MAX_HEADERS_SIZE);
}


static void iasp_reset_packet(bool encrypted)
{
    if(encrypted) {
        streambuf_init(&packet_sb, buf, 0, bufsize);
    }
    else {
        streambuf_init(&packet_sb, buf + sizeof(iasp_secure_header_t), 0, bufsize - sizeof(iasp_secure_header_t));
    }
}
