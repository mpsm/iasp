#ifndef __IASP_FFD_H__
#define __IASP_FFD_H__

#include "crypto.h"

typedef struct {
    crypto_ecdhe_context_t ecdhe_ctx;
} iasp_ffddata_t;

#endif
