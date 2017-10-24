#include "crypto.h"
#include "binbuf.h"
#include "types.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


/* private constants */
typedef struct {
    iasp_spn_code_t spn_code;
    int nid_ec;
    int nid_dgst;
    const EVP_MD *md;
} crypto_context_t;
static const crypto_context_t spn_map[] = {
        {IASP_SPN_128, NID_X9_62_prime256v1, NID_sha256},
        {IASP_SPN_256, NID_secp521r1, NID_sha512},
        {IASP_SPN_MAX, 0, 0},
};

/* private variables */
static EC_KEY *my_key = NULL;
static iasp_spn_code_t spn = IASP_SPN_MAX;
static iasp_identity_t my_id;


/* private methods */
static bool crypto_eckey2id(iasp_spn_code_t spn, EC_KEY *key, iasp_identity_t *id);
static const crypto_context_t *crypto_get_context(iasp_spn_code_t spn);


bool crypto_init(binbuf_t * const pkey)
{
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    int group_nid;
    int i = 0;

    assert(pkey != NULL);

    /* init OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_CRYPTO_strings();

    if(d2i_ECPrivateKey(&my_key, (const unsigned char **)&pkey->buf, pkey->size) == NULL) {
        return false;
    }

    group = EC_KEY_get0_group(my_key);
    group_nid = EC_GROUP_get_curve_name(group);
    printf("Curve: %s (%d)\n",  OBJ_nid2ln(group_nid), group_nid);


    while(spn_map[i].spn_code != IASP_SPN_MAX) {
        if(spn_map[i].nid_ec == group_nid) {
            spn = spn_map[i].spn_code;
        }
        i++;
    }

    if(spn == IASP_SPN_MAX) {
        printf("Cannot match SPN.\n");
        return false;
    }

    printf("Matched SPN profile: %u\n", (unsigned int)spn);

    pubkey = EC_KEY_get0_public_key(my_key);
    printf("Public key (compressed):   %s\n", EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_COMPRESSED, NULL));
    printf("Public key (uncompressed): %s\n", EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL));

    crypto_eckey2id(spn, my_key, &my_id);

    return true;
}


const iasp_identity_t* crypto_get_id()
{
    return &my_id;
}


void crypto_free()
{
    if(my_key != NULL) {
        EC_KEY_free(my_key);
    }
}


static const crypto_context_t *crypto_get_context(iasp_spn_code_t spn)
{
    const crypto_context_t *ctx = NULL;
    int i = 0;

    while(spn_map[i].spn_code != IASP_SPN_MAX) {
        if(spn_map[i].spn_code == spn) {
            return &spn_map[i];
        }
        i++;
    }

    return ctx;
}


static bool crypto_eckey2id(iasp_spn_code_t spn, EC_KEY *key, iasp_identity_t *id)
{
    const EVP_MD *md;
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    BIGNUM *bn;
    uint8_t *buf, *mdbuf;
    size_t buflen;
    const crypto_context_t *ctx;
    unsigned int mdsize;

    assert(key != NULL);

    /* get crypto handlers */
    ctx = crypto_get_context(spn);
    if(ctx == NULL) {
        return false;
    }
    //md = EVP_get_digestbynid(ctx->nid_dgst);
    md = EVP_get_digestbynid(NID_sha256);

    /* read public key */
    group = EC_KEY_get0_group(my_key);
    pubkey = EC_KEY_get0_public_key(my_key);
    bn = EC_POINT_point2bn(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
    buflen = BN_num_bytes(bn);
    buf = malloc(buflen);
    EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);

    /* calculate md */
    mdbuf = malloc(md->md_size);
    EVP_Digest(buf, buflen, mdbuf, &mdsize, md, NULL);
    memcpy(id->data, mdbuf, IASP_CONFIG_IDENTITY_SIZE);

    /* free */
    BN_free(bn);
    free(buf);
    free(mdbuf);

    return true;
}

