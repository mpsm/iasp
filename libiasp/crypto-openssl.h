#ifndef __CRYPTO_OPENSSL_H__
#define __CRYPTO_OPENSSL_H__

#include "types.h"

#include <stdbool.h>


bool crypto_openssl_extract_key(iasp_pkey_t * const pkey, iasp_identity_t * const id, const binbuf_t *bb);


#endif
