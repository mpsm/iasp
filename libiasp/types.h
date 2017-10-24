#ifndef __IASP_TYPES__H__
#define __IASP_TYPES__H__


#include "config.h"
#include <stdint.h>


typedef struct {
    uint8_t data[IASP_CONFIG_IDENTITY_SIZE];
} iasp_identity_t;;

typedef enum {
    IASP_SPN_128 = 1,
    IASP_SPN_256 = 2,

    /* sentinel */
    IASP_SPN_MAX,
} iasp_spn_code_t;


#endif
