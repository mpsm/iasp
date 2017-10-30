#include "proto.h"

#include <assert.h>
#include <stdbool.h>


void iasp_proto_put_inner_hdr(uint8_t *buf, bool encrypted, iasp_pv_t pv, iasp_spn_code_t spn)
{
    iasp_outer_header_t oh;

    assert(pv < IASP_PV_MAX);
    assert(spn < IASP_SPN_MAX);

    oh.bits.e = encrypted;
    oh.bits.pv = pv;
    oh.bits.spn = spn;

    *buf = oh.byte;
}


void iasp_proto_put_outer_hdr(uint8_t *buf, iasp_msg_type_t msg_type, bool answer, uint8_t pn)
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
