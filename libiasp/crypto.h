#ifndef __IASP_CRYPTO_H__
#define __IASP_CRYPTO_H__

#include "binbuf.h"
#include "types.h"

#include <stdbool.h>


bool crypto_init(void);
bool crypto_add_key(binbuf_t * const pkey);
void crypto_get_ids(iasp_ids_t * const ids);
bool crypto_gen_nonce(iasp_nonce_t *nonce);
void crypto_free(void);

iasp_spn_code_t crypto_choose_spn(const iasp_ids_t * const ids);
bool crypto_get_id(iasp_spn_code_t spn_code, iasp_identity_t *id);
const iasp_spn_support_t* crypto_get_supported_spns(void);

#endif
