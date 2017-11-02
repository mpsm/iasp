#include "crypto.h"
#include "crypto-openssl.h"
#include "binbuf.h"
#include "types.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

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
iasp_spn_support_t *spn = NULL;
const crypto_public_keys_t *public_keys = NULL;


/* private methods */
static bool crypto_eckey2id(iasp_spn_code_t spn, EC_KEY *key, iasp_identity_t *id);
static const crypto_context_t *crypto_get_context(iasp_spn_code_t spn);
static const iasp_spn_support_t *crypto_get_supported_spn(iasp_spn_code_t spn);
static iasp_spn_code_t crypto_match_spn(EC_KEY *key);
static bool crypto_get_public_key(EC_KEY *key, point_conversion_form_t format, uint8_t **buf, size_t *bufsize);


bool crypto_init()
{
    /* init OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_CRYPTO_strings();

    return true;
}


const iasp_spn_support_t* crypto_get_supported_spns()
{
    return spn;
}


void crypto_free()
{
    /* TODO: implement */
#if 0
    if(aux_data != NULL) {
        EC_KEY_free(aux_data);
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
    uint8_t *buf = NULL, *mdbuf;
    size_t buflen = 0;
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
    crypto_get_public_key(key, POINT_CONVERSION_UNCOMPRESSED, &buf, &buflen);

    /* calculate md */
    mdbuf = malloc(md->md_size);
    EVP_Digest(buf, buflen, mdbuf, &mdsize, md, NULL);
    memcpy(id->data, mdbuf, IASP_CONFIG_IDENTITY_SIZE);
    id->spn = spn;

    /* free */
    free(buf);
    free(mdbuf);

    return true;
}


static bool crypto_get_public_key(EC_KEY *key, point_conversion_form_t format, uint8_t **buf, size_t *bufsize)
{
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    BIGNUM *bn;
    size_t minbufsize;

    assert(buf != NULL);
    assert(bufsize != NULL);

    group = EC_KEY_get0_group(key);
    pubkey = EC_KEY_get0_public_key(key);
    bn = EC_POINT_point2bn(group, pubkey, format, NULL, NULL);
    minbufsize = BN_num_bytes(bn);
    if(*bufsize == 0 || minbufsize <= *bufsize) {
        *bufsize = minbufsize;
    }
    else {
        return false;
    }

    if(*buf == NULL) {
        *buf = malloc(*bufsize);
    }

    EC_POINT_point2oct(group, pubkey, format, *buf, *bufsize, NULL);
    BN_free(bn);

    return true;
}


static iasp_spn_code_t crypto_match_spn(EC_KEY *key)
{
    unsigned int i = 0;
    int group_nid;

    group_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));

    while(spn_map[i].spn_code != IASP_SPN_MAX) {
        if(spn_map[i].nid_ec == group_nid) {
            return spn_map[i].spn_code;
        }
        i++;
    }

    return IASP_SPN_NONE;
}


bool crypto_add_key(binbuf_t * const pkey)
{
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    EC_KEY *key = NULL;
    int group_nid;
    iasp_spn_support_t *cs = spn;
    iasp_spn_support_t *new_cs;
    iasp_spn_code_t new_spn;
    const unsigned char *key_data;

    assert(pkey != NULL);

    /* read key */
    key_data = pkey->buf;
    if(d2i_ECPrivateKey(&key, &key_data, pkey->size) == NULL) {
        return false;
    }

    /* extract curve nid */
    group = EC_KEY_get0_group(key);
    group_nid = EC_GROUP_get_curve_name(group);
    printf("Curve: %s (%d)\n",  OBJ_nid2ln(group_nid), group_nid);

    /* check if curve is used by known profile */
    new_spn = crypto_match_spn(key);
    if(new_spn == IASP_SPN_MAX || new_spn == IASP_SPN_NONE) {
            printf("Cannot match SPN.\n");
            return false;
    }

    printf("Matched SPN profile: %u\n", (unsigned int)new_spn);

    /* find out if SPN is already supported */
    while(cs != NULL) {
        const crypto_context_t *ctx = crypto_get_context(cs->id.spn);

        assert(ctx != NULL);

        if(ctx->nid_ec == group_nid) {
            printf("There is another key for this profile.\n");
            return false;
        }

        cs = cs->next;
    }

    /* print new key */
    pubkey = EC_KEY_get0_public_key(key);
    printf("Public key (compressed):   %s\n", EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_COMPRESSED, NULL));
    printf("Public key (uncompressed): %s\n", EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL));

    /* allocate new crypto support structure */
    new_cs = malloc(sizeof(iasp_spn_support_t));
    new_cs->aux_data = key;
    new_cs->id.spn = new_spn;

    crypto_eckey2id(new_spn, new_cs->aux_data, &new_cs->id);

    /* add crypto support to the list */
    if(spn == NULL) {
        spn = new_cs;
        spn->next = NULL;
    }
    else {
        new_cs->next = spn;
        spn = new_cs;
    }

    return true;
}


bool crypto_gen_nonce(iasp_nonce_t *nonce)
{
    return RAND_bytes(nonce->data, IASP_CONFIG_NONCE_SIZE) == 1;
}


void crypto_get_ids(iasp_ids_t * const ids)
{
    iasp_spn_support_t *cs = spn;
    unsigned int count = 0;

    assert(ids != NULL);

    while(cs != NULL) {
        if(count == IASP_MAX_IDS) {
            break;
        }

        /* copy ID */
        memcpy(ids->id[count].data, cs->id.data, sizeof(iasp_identity_t));

        /* set SPN */
        ids->id[count].spn = cs->id.spn;

        cs = cs->next;
        count++;
    }

    ids->id_count = count;
}


static const iasp_spn_support_t *crypto_get_supported_spn(iasp_spn_code_t spn_code)
{
    iasp_spn_support_t *s = spn;

    while(s != NULL) {
        if(s->id.spn == spn_code) {
            break;
        }
        s = s->next;
    }

    return s;
}


iasp_spn_code_t crypto_choose_spn(const iasp_ids_t * const ids)
{
    unsigned int i;

    assert(ids != NULL);

    for(i = IASP_SPN_MAX - 1; i > IASP_SPN_NONE; i--) {
        const iasp_spn_support_t *s = crypto_get_supported_spn(i);
        unsigned int j;

        /* spn is unsupported */
        if(s == NULL) {
            continue;
        }

        /* check if supported by peer */
        for(j = 0; j < ids->id_count; ++j) {
            if(ids->id[j].spn == i) {
                /* found matching SPN */
                return i;
            }
        }
    }

    return IASP_SPN_NONE;
}


bool crypto_get_id(iasp_spn_code_t spn_code, iasp_identity_t *id)
{
    const iasp_spn_support_t *s = crypto_get_supported_spn(spn_code);

    assert(id != NULL);

    if(s == NULL) {
        return false;
    }

    memcpy(id, &s->id, sizeof(iasp_identity_t));
    return true;
}


bool crypto_openssl_extract_key(iasp_pkey_t * const pkey, iasp_identity_t * const id, const binbuf_t *bb)
{
    EVP_PKEY *evppkey;
    EC_KEY *eckey;
    const unsigned char *key_data;
    unsigned char *okey_data;
    size_t keysize;
    iasp_spn_code_t matched_spn;

    assert(pkey != NULL);
    assert(bb != NULL);

    key_data = bb->buf;
    keysize = sizeof(pkey->pkeydata);

    /* read public key */
    evppkey = d2i_PUBKEY( NULL, &key_data, bb->size);
    if(evppkey == NULL) {
        return false;
    }

    /* get EC key */
    eckey = EVP_PKEY_get1_EC_KEY(evppkey);
    if(eckey == NULL) {
        return false;
    }

    /* find SPN of a key */
    matched_spn = crypto_match_spn(eckey);
    if(matched_spn == IASP_SPN_MAX || matched_spn == IASP_SPN_NONE) {
        return false;
    }

    /* get EC key data */
    okey_data = pkey->pkeydata;
    if(!crypto_get_public_key(eckey, POINT_CONVERSION_COMPRESSED, &okey_data, &keysize)) {
        return false;
    }
    pkey->spn = matched_spn;

    /* calculate ID */
    if(id != NULL) {
        crypto_eckey2id(matched_spn, eckey, id);
    }
    return true;
}


void crypto_set_pubkeys(const crypto_public_keys_t * const pubkeys)
{
    public_keys = pubkeys;
}


/* signing */

static EVP_MD_CTX sign_ctx;
static iasp_spn_code_t sign_spn;


bool crypto_sign_init(iasp_spn_code_t spn_code)
{
    const iasp_spn_support_t *cs = crypto_get_supported_spn(spn_code);
    unsigned int i = 0;
    const EVP_MD *md = NULL;
    EVP_PKEY pkey;

    /* check SPN */
    if(cs == NULL) {
        return false;
    }

    /* get proper MD */
    while(spn_map[i].spn_code != IASP_SPN_MAX) {
        if(spn_map[i].spn_code == spn_code) {
            md = EVP_get_digestbynid(spn_map[i].nid_dgst);
            break;
        }
        i++;
    }
    if(i == IASP_SPN_MAX) {
        /* MD not found */
        return false;
    }
    sign_spn = spn_code;

    /* init sign context */
    EVP_MD_CTX_init(&sign_ctx);
    if(EVP_PKEY_set1_EC_KEY(&pkey, (EC_KEY *)cs->aux_data) == 0) {
        return false;
    }
    EVP_DigestSignInit(&sign_ctx, NULL, md, NULL, &pkey);

    return true;
}


bool crypto_sign_update(const binbuf_t * const bb)
{
    return EVP_DigestSignUpdate(&sign_ctx, bb->buf, bb->size) != 0;
}


bool crypto_sign_final(iasp_sig_t * const sig)
{
    size_t siglen = sizeof(sig->sigdata);

    assert(sig != NULL);

    sig->spn = sign_spn;
    if(EVP_DigestSignFinal(&sign_ctx, sig->sigdata, &siglen) == 0) {
        return false;
    }
    sig->siglen = siglen;

    return true;
}
