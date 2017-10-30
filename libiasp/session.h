#ifndef __IASP_SESSION_H__
#define __IASP_SESSION_H__

#include "network.h"
#include "proto.h"
#include "types.h"

#include <stdint.h>
#include <stdbool.h>


typedef struct {
    iasp_pv_t pv;
    iasp_spn_code_t spn;
    uint8_t pn;
    //bool encrypted;
    const iasp_address_t *my_addr;
    const iasp_address_t *peer_addr;
} iasp_session_t;


void iasp_session_init(iasp_session_t * const this, const iasp_address_t *addr, const iasp_address_t *peer_addr);
void iasp_session_start(iasp_session_t * const this);


#endif
