#ifndef __IASP_CRYPTO_H__
#define __IASP_CRYPTO_H__

#include "binbuf.h"
#include "types.h"

#include <stdbool.h>


bool crypto_init(void);
bool crypto_add_key(binbuf_t * const pkey);
const iasp_identity_t* crypto_get_id(void);
void crypto_free(void);


#endif
