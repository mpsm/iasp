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
    iasp_spn_code_t spn;
} crypto_ecdhe_context_t;


/* init and destroy */
bool crypto_init(void);
void crypto_destroy(void);

/* getters */
bool crypto_get_id(iasp_spn_code_t spn_code, iasp_identity_t *id);
void crypto_get_ids(iasp_ids_t * const ids);
bool crypto_get_pkey(iasp_spn_code_t, iasp_pkey_t * const pkey);
size_t crypto_get_pkey_length(iasp_spn_code_t spn, bool compressed);

/* misc */
bool crypto_add_key(binbuf_t * const pkey);
bool crypto_gen_nonce(iasp_nonce_t *nonce);
bool crypto_gen_key(iasp_spn_code_t spn, iasp_key_t *const key);
bool crypto_gen_salt(iasp_salt_t * const salt);
iasp_spn_code_t crypto_choose_spn(const iasp_ids_t * const ids);
iasp_spn_code_t crypto_choose_spn2(const iasp_ids_t * const iids, const iasp_ids_t * const rids);
const iasp_identity_t * crypto_id_by_spn(iasp_spn_code_t spn, const iasp_ids_t * const ids);

/* public keys */
void crypto_set_pubkeys(const crypto_public_keys_t * const pubkeys);
const iasp_pkey_t *crypto_get_pkey_by_id(const iasp_identity_t * const id);

/* signing */
size_t crypto_get_sign_length(iasp_spn_code_t spn_code, iasp_sigtype_t sigtype);
bool crypto_sign_init(iasp_spn_code_t spn_code, iasp_sigtype_t sigtype);
bool crypto_sign_update(const unsigned char *b, size_t blen);
bool crypto_sign_update_bb(const binbuf_t * const bb);
bool crypto_sign_final(iasp_sig_t * const sig);

/* sign verify */
bool crypto_verify_init(const iasp_identity_t * const id, iasp_sigtype_t sigtype);
bool crypto_verify_update(const unsigned char *b, size_t blen);
bool crypto_verify_final(const iasp_sig_t * const sig);

/* ECDHE */
bool crypto_ecdhe_genkey(iasp_spn_code_t spn_code, iasp_pkey_t *pkey, crypto_ecdhe_context_t *ecdhe_ctx);
bool crypto_ecdhe_compute_secret(const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx,
        uint8_t *secret, size_t secretlen, const binbuf_t * const salt);
bool crypto_ecdhe_pkey(const crypto_ecdhe_context_t *ecdhe_ctx, iasp_pkey_t * const pkey);

/* symmetric crypto */
size_t crypto_get_key_size(iasp_spn_code_t spn);

/* OOB key authentication */
void crypto_set_oob_key(const binbuf_t * const bb);


#endif
