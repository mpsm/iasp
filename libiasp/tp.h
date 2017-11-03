#ifndef __IASP_TP_H__
#define __IASP_TP_H__

#include "crypto.h"
#include "types.h"


typedef struct {
    crypto_ecdhe_context_t ecdhe_ctx;
} iasp_tpdata_t;


void iasp_tpdata_init(iasp_tpdata_t * const this);


#endif
