#ifndef __IASP_CRYPTO_H__
#define __IASP_CRYPTO_H__

#include "binbuf.h"
#include "types.h"

#include <stdbool.h>


bool crypto_init(binbuf_t * const pkey);
iasp_identity_t crypto_get_id(void);
void crypto_free(void);


#endif
