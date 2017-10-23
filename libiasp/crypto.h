#ifndef __IASP_CRYPTO_H__
#define __IASP_CRYPTO_H__

#include "binbuf.h"

#include <stdbool.h>


bool crypto_init(binbuf_t * const pkey);
void crypto_free(void);


#endif
