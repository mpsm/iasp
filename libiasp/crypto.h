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


typedef struct{
    void *ctx;
} crypto_ecdhe_context_t;


bool crypto_init(void);
bool crypto_add_key(binbuf_t * const pkey);
void crypto_get_ids(iasp_ids_t * const ids);
bool crypto_gen_nonce(iasp_nonce_t *nonce);
void crypto_free(void);

iasp_spn_code_t crypto_choose_spn(const iasp_ids_t * const ids);
bool crypto_get_id(iasp_spn_code_t spn_code, iasp_identity_t *id);
const iasp_spn_support_t* crypto_get_supported_spns(void);
void crypto_set_pubkeys(const crypto_public_keys_t * const pubkeys);

/* public keys */
size_t crypto_get_pkey_length(iasp_spn_code_t spn, bool compressed);

/* signing */
size_t crypto_get_sign_length(iasp_spn_code_t spn_code);
bool crypto_sign_init(iasp_spn_code_t spn_code);
bool crypto_sign_update(const unsigned char *b, size_t blen);
bool crypto_sign_update_bb(const binbuf_t * const bb);
bool crypto_sign_final(iasp_sig_t * const sig);

/* sign verify */
bool crypto_verify_init(const iasp_identity_t * const id);
bool crypto_verify_update(const unsigned char *b, size_t blen);
bool crypto_verify_final(const iasp_sig_t * const sig);

/* ECDHE */
bool crypto_ecdhe_genkey(iasp_spn_code_t spn_code, iasp_pkey_t *pkey, crypto_ecdhe_context_t *ecdhe_ctx);
bool crypto_ecdhe_compute_secret(void);


#endif
