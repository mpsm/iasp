#ifndef __IASP_FIELD_H__
#define __IASP_FIELD_H__


#include <stdint.h>

#include "streambuf.h"
#include "security.h"
#include "config.h"


typedef enum {
    IASP_FIELD_NONCE = 1,
    IASP_FIELD_PKEY = 2,
    IASP_FIELD_SIG = 3,
    IASP_FIELD_ID = 4,
    IASP_FIELD_SKEY = 5,
    IASP_FIELD_SPN = 6,
    IASP_FIELD_KPARAM = 7,
    IASP_FIELD_IP = 9,
    IASP_FIELD_CERTSTATUS = 10,
    IASP_FIELD_TOKEN = 11,
    IASP_FIELD_SID = 12,
    IASP_FIELD_OPSTATUS = 13,
    IASP_FIELD_HINT = 14,
    IASP_FIELD_SPI = 15,
    IASP_FIELD_KEY = 16,
    IASP_FIELD_SIGTYPE = 17,
    IASP_FIELD_SETOF = 127,
} iasp_field_code_t;


typedef uint16_t iasp_field_spi_t;
typedef uint32_t iasp_field_token_t;


typedef enum {
    IASP_OPSTATUS_OK = 0,
    IASP_OPSTATUS_ERROR = 1,
    IASP_OPSTATUS_EINVAL = 2,
    /* TODO: define operation status */
} iasp_field_opstatus_t;

#if 0
typedef struct {
    union {
        struct {
            iasp_field_nonce_t nonce;
            iasp_field_spi_t initiator_spi;
            iasp_field_spi_t responder_spi;
        } sid;
        uint64_t sidnum;
        uint8_t sidbuf[sizeof(iasp_field_nonce_t) + 2*sizeof(iasp_field_spi_t)];
    };
} iasp_field_sid_t;
#endif


typedef struct {
    uint8_t *keydata;
    iasp_spn_code_t spn;
} iasp_field_key_t;


#endif
