#ifndef __IASP_CRYPTO_H__
#define __IASP_CRYPTO_H__

#include "binbuf.h"
#include "types.h"

#include <stdbool.h>
#include <stddef.h>


typedef struct {
    size_t count;
    struct {
        iasp_pkey_t pubkey;
        iasp_identity_t id;
    } *keys;
} crypto_public_keys_t;


bool crypto_init(void);
bool crypto_add_key(binbuf_t * const pkey);
void crypto_get_ids(iasp_ids_t * const ids);
bool crypto_gen_nonce(iasp_nonce_t *nonce);
void crypto_free(void);

iasp_spn_code_t crypto_choose_spn(const iasp_ids_t * const ids);
bool crypto_get_id(iasp_spn_code_t spn_code, iasp_identity_t *id);
const iasp_spn_support_t* crypto_get_supported_spns(void);
void crypto_set_pubkeys(const crypto_public_keys_t * const pubkeys);

#endif
