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

/* typedefs */
typedef struct _crypto_support {
    iasp_spn_code_t spn_code;
    EC_KEY *my_key;
    iasp_identity_t my_id;
    struct _crypto_support *next;
} crypto_support_t;


/* private variables */
crypto_support_t *spn = NULL;


/* private methods */
static bool crypto_eckey2id(iasp_spn_code_t spn, EC_KEY *key, iasp_identity_t *id);
static const crypto_context_t *crypto_get_context(iasp_spn_code_t spn);


bool crypto_init()
{
    /* init OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_CRYPTO_strings();

    return true;
}


const iasp_identity_t* crypto_get_id()
{
    /* TODO: implement */
#if 0
    return &my_id;
#else
    return NULL;
#endif
}


void crypto_free()
{
    /* TODO: implement */
#if 0
    if(my_key != NULL) {
        EC_KEY_free(my_key);
    }
#endif
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
    md = EVP_get_digestbynid(NID_sha256);

    /* read public key */
    group = EC_KEY_get0_group(key);
    pubkey = EC_KEY_get0_public_key(key);
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


bool crypto_add_key(binbuf_t * const pkey)
{
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    EC_KEY *key;
    int group_nid;
    int i;
    crypto_support_t *cs = spn;
    crypto_support_t *new_cs;
    iasp_spn_code_t new_spn;

    assert(pkey != NULL);

    /* read key */
    if(d2i_ECPrivateKey(&key, (const unsigned char **)&pkey->buf, pkey->size) == NULL) {
        return false;
    }

    /* extract curve nid */
    group = EC_KEY_get0_group(key);
    group_nid = EC_GROUP_get_curve_name(group);
    printf("Curve: %s (%d)\n",  OBJ_nid2ln(group_nid), group_nid);

    /* check if curve is used by known profile */
    i = 0;
    while(spn_map[i].spn_code != IASP_SPN_MAX) {
        if(spn_map[i].nid_ec == group_nid) {
            new_spn = spn_map[i].spn_code;
        }
        i++;
    }
    if(new_spn == IASP_SPN_MAX) {
            printf("Cannot match SPN.\n");
            return false;
    }
    printf("Matched SPN profile: %u\n", (unsigned int)new_spn);

    /* find out if SPN is already supported */
    while(cs != NULL) {
        const crypto_context_t *ctx = crypto_get_context(cs->spn_code);

        assert(ctx != NULL);

        if(ctx->nid_ec == group_nid) {
            printf("There is another key for this profile.\n");
            return false;
        }
    }

    /* print new key */
    pubkey = EC_KEY_get0_public_key(key);
    printf("Public key (compressed):   %s\n", EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_COMPRESSED, NULL));
    printf("Public key (uncompressed): %s\n", EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL));

    /* allocate new crypto support structure */
    new_cs = malloc(sizeof(crypto_support_t));
    new_cs->my_key = key;
    new_cs->spn_code = new_spn;
    crypto_eckey2id(new_spn, new_cs->my_key, &new_cs->my_id);

    /* add crypto support to the list */
    if(spn == NULL) {
        spn = new_cs;
    }
    else {
        new_cs->next = spn;
        spn = new_cs;
    }

    return true;
}
