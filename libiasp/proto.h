#ifndef __IASP_PROTO_H__
#define __IASP_PROTO_H__

#include "types.h"
#include "network.h"
#include "streambuf.h"

#include <stdbool.h>
#include <stdint.h>

/* INFO: might be compiler-dependent (C99 6.7.2.1/4) */

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
    iasp_spi_t spi;
    uint32_t seq;
} __attribute__((packed)) iasp_secure_header_t;

typedef union {
    struct {
        unsigned char r:    1;
        unsigned char mt:   2;
        unsigned char a:    1;
        unsigned char pn:   4;
    } bits;
    uint8_t byte;
} iasp_inner_hdr_t;

typedef struct {
    iasp_address_t addr;
    iasp_address_t peer;
    bool encrypted;
    bool answer;
    iasp_pv_t pv;
    iasp_spn_code_t spn;
    iasp_msg_type_t msg_type;
    uint8_t pn;
    uint32_t input_seq;
    uint32_t output_seq;
    iasp_spi_t input_spi;
    iasp_spi_t output_spi;
} iasp_proto_ctx_t;


#define IASP_PROTO_HEADERS_SIZE (sizeof(iasp_inner_hdr_t) + sizeof(iasp_outer_hdr_t))
#define IASP_PROTO_MAX_HEADERS_SIZE (sizeof(iasp_inner_hdr_t) + sizeof(iasp_outer_header_t) + sizeof(iasp_secure_header_t))


void iasp_proto_ctx_init(iasp_proto_ctx_t * const this);
void iasp_proto_bump_pn(iasp_proto_ctx_t * const this);
void iasp_proto_init(uint8_t * obuf, size_t obuflen);
streambuf_t * iasp_proto_get_payload_sb(void);
void iasp_proto_reset_payload(void);
bool iasp_proto_get_inner_header(iasp_proto_ctx_t * const pctx);
bool iasp_proto_set_headers(iasp_proto_ctx_t * const this);
void iasp_proto_put_outer_hdr(uint8_t *buf, bool encrypted, iasp_pv_t pv, iasp_spn_code_t spn);
void iasp_proto_put_inner_hdr(uint8_t *buf, iasp_msg_type_t msg_type, bool answer, uint8_t pn);
bool iasp_proto_put_security_hdr(streambuf_t *sb, iasp_spi_t spi, uint32_t seq);
bool iasp_proto_send(iasp_proto_ctx_t * const this, streambuf_t * const payload);
bool iasp_proto_receive(iasp_address_t * const address, iasp_proto_ctx_t * const pctx, streambuf_t * const payload,
        unsigned int timeout);


#endif
