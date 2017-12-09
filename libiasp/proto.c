#include "proto.h"
#include "network.h"
#include "streambuf.h"
#include "binbuf.h"
#include "types.h"
#include "debug.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


/* private fields */
size_t bufsize;
uint8_t *buf;
streambuf_t packet_sb;
streambuf_t payload_sb;


/* private methods */
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


bool iasp_proto_put_security_hdr(streambuf_t *sb, iasp_spi_t spi, uint32_t seq)
{
    uint32_t nseq = htonl(seq);
    return streambuf_write(sb, spi.spidata, sizeof(iasp_spi_t)) && streambuf_write(sb, (uint8_t *)&nseq, sizeof(nseq));
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


bool iasp_proto_send(iasp_proto_ctx_t * const this, streambuf_t * const payload)
{
    uint8_t oh, ih;
    uint8_t pn = this->pn;
    binbuf_t bb;

    assert(this != NULL);

    /* prepare packet sb */
    iasp_reset_packet(this->encrypted);

    /* prepare headers */
    iasp_proto_put_outer_hdr(&oh, this->encrypted, this->pv, this->spn);
    iasp_proto_put_inner_hdr(&ih, this->msg_type, this->answer, pn);

    /* put headers */
    if(!streambuf_write(&packet_sb, &oh, sizeof(oh))) {
        return false;
    }
    if(this->encrypted && !iasp_proto_put_security_hdr(&packet_sb, this->output_spi, this->output_seq)) {
        return false;
    }
    if(!streambuf_write(&packet_sb, &ih, sizeof(ih))) {
        return false;
    }

    /* prepare descriptor */
    bb.buf = packet_sb.data;
    bb.size = packet_sb.size;
    if(payload != NULL && payload != &payload_sb) {
        if(!streambuf_write_sb(&packet_sb, payload)) {
            return false;
        }
        bb.size = packet_sb.size;
    }
    else {
        bb.size = packet_sb.size + payload_sb.size;
    }

    /* send packet */
    if(!iasp_network_send(&this->addr, &this->peer, &bb)) {
        return false;
    }

    this->pn = pn;

    return true;
}


void iasp_proto_init(uint8_t * obuf, size_t obuflen)
{
    assert(obuflen > 0);
    assert(obuf != NULL);

    buf = obuf;
    bufsize = obuflen;

    memset(buf, 0, bufsize);

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


void iasp_proto_ctx_init(iasp_proto_ctx_t * const this)
{
    assert(this != NULL);

    memset(this, 0, sizeof(iasp_proto_ctx_t));
}


void iasp_proto_bump_pn(iasp_proto_ctx_t * const this)
{
    assert(this != NULL);

    this->pn = (this->pn + 1) & (IASP_PROTO_PN_MAX - 1);
}


bool iasp_proto_get_inner_header(iasp_proto_ctx_t * const pctx)
{
    iasp_inner_hdr_t ih;

    /* read inner header */
    if(!streambuf_read(&payload_sb, &ih.byte, sizeof(ih))) {
        return false;
    }
    pctx->msg_type = ih.bits.mt;
    pctx->answer = ih.bits.a;
    pctx->pn = ih.bits.pn;

    return true;
}


bool iasp_proto_receive(iasp_address_t * const addr, iasp_proto_ctx_t * const pctx, streambuf_t * const payload,
        unsigned int timeout)
{
    binbuf_t bb;
    iasp_outer_header_t oh;
    iasp_secure_header_t sh;
    streambuf_t *psb;
    size_t payload_size;

    assert(pctx != NULL);

    /* reset proto context */
    iasp_proto_ctx_init(pctx);

    /* prepare descriptor */
    bb.buf = buf;
    bb.size = bufsize;

    /* reset receive buffer */
    memset(bb.buf, 0, bb.size);

    /* receive msg */
    if(!iasp_network_receive(addr, &pctx->peer, &bb, timeout)) {
        return false;
    }
    memcpy(&pctx->addr, addr, sizeof(iasp_address_t));

    /* init streambuf */
    streambuf_init(&packet_sb, bb.buf, bb.size, bufsize);

    /* read outer header */
    if(!streambuf_read(&packet_sb, &oh.byte, sizeof(oh))) {
        return false;
    }
    pctx->encrypted = oh.bits.e;
    pctx->spn = oh.bits.spn;
    pctx->pv = oh.bits.pv;

    /* read secure header if encrypted */
    if(pctx->encrypted) {
        if(!streambuf_read(&packet_sb, (uint8_t *)&sh, sizeof(sh))) {
            return false;
        }
        pctx->input_seq = ntohl(sh.seq);
        pctx->input_spi = sh.spi;
    }

    /* set payload */
    psb = payload == NULL ? &payload_sb : payload;
    payload_size = packet_sb.size - packet_sb.read_index;
    streambuf_init(psb, packet_sb.data + packet_sb.read_index, payload_size, payload_size);

    /* debug */
    debug_log("Message received: %s, answer: %s, PV=%u, SPN=%u, payload size: %u bytes.\n",
            pctx->encrypted ? "encrypted" : "not encrypted",
            pctx->answer ? "yes" : "no", pctx->pv, pctx->spn, psb->size);
    if(pctx->encrypted) {
        debug_log("Packet SPI: ");
        debug_print_spi(&sh.spi);
        debug_newline();
        debug_log("Packet SEQ: ");
        debug_print_binary((uint8_t *)&sh.seq, sizeof(sh.seq));
        debug_newline();
    }

    return true;
}
