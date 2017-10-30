#ifndef __IASP_SESSION_H__
#define __IASP_SESSION_H__

#include "proto.h"
#include "types.h"

#include <stdint.h>
#include <stdbool.h>


typedef struct {
    iasp_pv_t pv;
    iasp_spn_code_t spn;
    uint8_t pn;
    bool encrypted;
} iasp_session_t;


void iasp_session_init(iasp_session_t * const this);


#endif
