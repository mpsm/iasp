#ifndef __IASP_PROTO_H__
#define __IASP_PROTO_H__

#include "types.h"

#include <stdbool.h>
#include <stdint.h>

/* INFO: might be compiler-dependent (C99 6.7.2.1/4)*/

#define IASP_PROTO_PN_MAX (1 << 4)

typedef enum {
    IASP_PV_0 = 0,
    IASP_PV_1 = 1,
    IASP_PV_2 = 2,
    IASP_PV_3 = 3,
    IASP_PV_4 = 4,
    IASP_PV_5 = 5,
    IASP_PV_6 = 6,
    IASP_PV_7 = 7,

    /* sentinel */
    IASP_PV_MAX
} iasp_pv_t;

typedef enum {
    IASP_MSG_HANDSHAKE =    0,
    IASP_MSG_MGMT =         1,
    IASP_MSG_USER =         2,

    /* sentinel */
    IASP_MSG_MAX
} iasp_msg_type_t;

typedef union {
    struct {
        unsigned char e:    1;
        unsigned char pv:   3;
        unsigned char spn:  4;
    } bits;
    uint8_t byte;
} iasp_outer_header_t;

typedef struct {
    uint16_t spi;
    uint32_t seq;
} iasp_secure_header_t;

typedef union {
    struct {
        unsigned char r:    1;
        unsigned char mt:   2;
        unsigned char a:    1;
        unsigned char pn:   4;
    } bits;
    uint8_t byte;
} iasp_inner_hdr_t;


void iasp_proto_put_outer_hdr(uint8_t *buf, bool encrypted, iasp_pv_t pv, iasp_spn_code_t spn);
void iasp_proto_put_inner_hdr(uint8_t *buf, iasp_msg_type_t msg_type, bool answer, uint8_t pn);

#endif
