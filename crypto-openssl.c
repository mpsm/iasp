#include "crypto-openssl.h"

#include "libiasp/crypto.h"

#include "libiasp/binbuf.h"
#include "libiasp/types.h"
#include "libiasp/config.h"
#include "libiasp/debug.h"
#include "libiasp/spn.h"
#include "libiasp/security.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


/* private constants */
typedef struct {
    iasp_spn_code_t spn_code;
    int nid_ec;
    unsigned int eclen;
    unsigned int dlen;
    int nid_dgst;
    size_t keysize;
    void *(*kdf)(const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const binbuf);
    const EVP_CIPHER *(*ccm)(void);
} crypto_context_t;
static void *kdf_spn1(const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const binbuf);
static void *kdf_spn2(const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const binbuf);
static void *kdf_common(const EVP_MD *md, const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const binbuf);

static const crypto_context_t spn_map[] = {
        {IASP_SPN_NONE, 0, 0, 0, 0, 0, NULL, NULL},
        {IASP_SPN_128, NID_X9_62_prime256v1, 32, 32, NID_sha256, 16, kdf_spn1, EVP_aes_128_ccm},
        {IASP_SPN_256, NID_secp521r1, 66, 64, NID_sha512, 32, kdf_spn2, EVP_aes_256_ccm},
        {IASP_SPN_MAX, 0, 0, 0, 0, 0, NULL, NULL},
};


/* private variables */
iasp_spn_support_t *spn = NULL;
const binbuf_t * oob = NULL;

/* sign and verify context */
static EVP_MD_CTX sign_ctx;
static iasp_spn_code_t sign_spn;
static EVP_PKEY sign_pkey;
static ASN1_OCTET_STRING sign_key;
static iasp_sigtype_t sign_type;


/* private methods */
static bool crypto_eckey2id(iasp_spn_code_t spn, EC_KEY *key, iasp_identity_t *id);
static const crypto_context_t *crypto_get_context(iasp_spn_code_t spn);
static const iasp_spn_support_t *crypto_get_supported_spn(iasp_spn_code_t spn);
static iasp_spn_code_t crypto_match_spn(EC_KEY *key);
static bool crypto_get_public_key(EC_KEY *key, point_conversion_form_t format, uint8_t **buf, size_t *bufsize);
bool crypto_pkey_to_evp(const iasp_pkey_t * const pkey, EVP_PKEY *evppkey);

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


bool crypto_get_pkey_id(iasp_pkey_t * const pkey, iasp_identity_t * const id)
{
    EVP_PKEY evp_pkey;
    EC_KEY *eckey;

    memset(&evp_pkey, 0, sizeof(evp_pkey));
    EVP_PKEY_set_type(&evp_pkey, EVP_PKEY_EC);

    /* initiate EVP_PKEY */
    if(!crypto_pkey_to_evp(pkey, &evp_pkey)) {
        return false;
    }

    /* get eckey */
    eckey = EVP_PKEY_get1_EC_KEY(&evp_pkey);
    if(eckey == NULL) {
        return false;
    }

    /* set id SPN */
    id->spn = pkey->spn;

    return crypto_eckey2id(pkey->spn, eckey, id);
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


bool crypto_openssl_add_key(binbuf_t * const pkey)
{
    const EC_GROUP *group;
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

    /* check if curve is used by known profile */
    new_spn = crypto_match_spn(key);
    if(new_spn == IASP_SPN_MAX || new_spn == IASP_SPN_NONE) {
            printf("Cannot match SPN.\n");
            return false;
    }

    debug_log("Matched SPN profile: %u\n", (unsigned int)new_spn);

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


iasp_spn_code_t security_choose_spn(const iasp_ids_t * const ids)
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


iasp_spn_code_t security_choose_spn2(const iasp_ids_t * const iids, const iasp_ids_t * const rids)
{
    unsigned int i;

    assert(iids != NULL);
    assert(rids != NULL);

    for(i = IASP_SPN_MAX - 1; i > IASP_SPN_NONE; i--) {
        unsigned int j;

        /* check if supported by peer */
        for(j = 0; j < iids->id_count; ++j) {
            if(iids->id[j].spn == i) {
                /* found matching SPN */
                break;
            }
        }

        /* spn not found */
        if(j == IASP_SPN_MAX) {
            continue;
        }

        /* check other peer */
        for(j = 0; j < rids->id_count; ++j) {
            if(rids->id[j].spn == i) {
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


bool crypto_openssl_extract_key_bb(iasp_pkey_t * const pkey, iasp_identity_t * const id, const binbuf_t *bb)
{
    EVP_PKEY *evppkey;
    const unsigned char *key_data;
    bool result = false;

    assert(bb != NULL);

    key_data = bb->buf;

    /* read public key */
    evppkey = d2i_PUBKEY(NULL, &key_data, bb->size);
    if(evppkey == NULL) {
        return false;
    }

    if(!crypto_openssl_extract_key(pkey, id, evppkey)) {
        goto end;
    }

    result = true;
end:
    if(evppkey) {
        EVP_PKEY_free(evppkey);
    }

    return result;
}


bool crypto_openssl_extract_key(iasp_pkey_t * const pkey, iasp_identity_t * const id, EVP_PKEY *evppkey)
{
    EC_KEY *eckey = NULL;
    unsigned char *okey_data = NULL;
    iasp_spn_code_t matched_spn;
    bool result = false;
    size_t keysize = 0;

    assert(pkey != NULL);
    assert(evppkey != NULL);

    /* get EC key */
    eckey = EVP_PKEY_get1_EC_KEY(evppkey);
    if(eckey == NULL) {
        goto error;
    }

    /* find SPN of a key */
    matched_spn = crypto_match_spn(eckey);
    if(matched_spn == IASP_SPN_MAX || matched_spn == IASP_SPN_NONE) {
        goto error;
    }

    /* get EC key data */
    okey_data = pkey->pkeydata;
    keysize = sizeof(pkey->pkeydata);
    if(!crypto_get_public_key(eckey, POINT_CONVERSION_COMPRESSED, &okey_data, &keysize)) {
        goto error;
    }
    pkey->spn = matched_spn;
    pkey->pkeylen = keysize;

    /* calculate ID */
    if(id != NULL) {
        crypto_eckey2id(matched_spn, eckey, id);
    }

    result = true;

error:
    if(eckey) {
        EC_KEY_free(eckey);
    }

    return result;
}


bool crypto_sign_init(iasp_spn_code_t spn_code, iasp_sigtype_t sigtype)
{
    const iasp_spn_support_t *cs = crypto_get_supported_spn(spn_code);
    unsigned int i = 0;
    const EVP_MD *md = NULL;

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

    /* reset pkey */
    memset(&sign_pkey, 0, sizeof(sign_pkey));

    /* init pkey */
    switch(sigtype) {
        case IASP_SIG_EC:
            EVP_PKEY_set_type(&sign_pkey, EVP_PKEY_EC);
            if(EVP_PKEY_set1_EC_KEY(&sign_pkey, (EC_KEY *)cs->aux_data) == 0) {
                return false;
            }
            break;

        case IASP_SIG_HMAC:
            if(oob == NULL) {
                return false;
            }

            /* correct key length */
            if(md->md_size < oob->size) {
                sign_key.length = md->md_size;
            }


            EVP_PKEY_set_type(&sign_pkey, EVP_PKEY_HMAC);
            EVP_PKEY_assign(&sign_pkey, EVP_PKEY_HMAC, &sign_key);
            break;

        default:
            abort();
    }
    sign_type = sigtype;

    /* init sign context */
    EVP_DigestSignInit(&sign_ctx, NULL, md, NULL, &sign_pkey);

    return true;
}


bool crypto_sign_update_bb(const binbuf_t * const bb)
{
    return EVP_DigestSignUpdate(&sign_ctx, bb->buf, bb->size) != 0;
}


bool crypto_sign_final(iasp_sig_t * const sig)
{
    size_t siglen;
    static unsigned char *sigbuf = NULL;
    static const unsigned char *psigbuf;
    size_t dlen;
    ECDSA_SIG* ecdsa;

    assert(sig != NULL);

    /* 7 bytes for DER structure, 2 * group size for (r, s) pair */
    EVP_DigestSignFinal(&sign_ctx, NULL, &siglen);
    debug_log("Signature length: %d\n", siglen);
    psigbuf = sigbuf = malloc(siglen);

    /* finish signing */
    if(EVP_DigestSignFinal(&sign_ctx, sigbuf, &siglen) == 0) {
        return false;
    }

    /* set sig */
    memset(sig->sigdata, 0, sizeof(sig->sigdata));
    switch(sign_type) {
        case IASP_SIG_EC:
            dlen = spn_map[sign_spn].eclen;
            ecdsa = d2i_ECDSA_SIG(NULL, &psigbuf, siglen);
            BN_bn2bin(ecdsa->r, sig->sigdata + (dlen - BN_num_bytes(ecdsa->r)));
            BN_bn2bin(ecdsa->s, sig->sigdata + (2*dlen - BN_num_bytes(ecdsa->s)));
            sig->siglen = dlen * 2;
            break;

        case IASP_SIG_HMAC:
            memcpy(sig->sigdata, sigbuf, siglen);
            sig->siglen = siglen;
            break;

        default:
            abort();
    }
    sig->spn = sign_spn;
    sig->sigtype = sign_type;
    free(sigbuf);

    return true;
}


bool crypto_sign_update(const unsigned char *b, size_t blen)
{
    debug_log("Adding data to sign: ");
    debug_print_binary(b, blen);
    debug_newline();
    return EVP_DigestSignUpdate(&sign_ctx, b, blen) != 0;
}


bool crypto_pkey_to_evp(const iasp_pkey_t * const pkey, EVP_PKEY *evppkey)
{
    EC_POINT *ecpoint;
    EC_KEY *eckey;
    const EC_GROUP *group;

    group = EC_GROUP_new_by_curve_name(spn_map[pkey->spn].nid_ec);
    assert(group != NULL);
    ecpoint = EC_POINT_new(group);
    eckey = EC_KEY_new();
    EC_KEY_set_group(eckey, group);

    if(EC_POINT_oct2point(
            group,
            ecpoint,
            pkey->pkeydata,
            spn_map[pkey->spn].eclen + 1,
            NULL) == 0) {
        return false;
    }
    if(EC_KEY_set_public_key(eckey, ecpoint) == 0) {
        return false;
    }
    if(EVP_PKEY_set1_EC_KEY(evppkey, eckey) == 0) {
        return false;
    }

    return true;
}


bool crypto_verify_init(const iasp_identity_t * const id, iasp_sigtype_t sigtype)
{
    const EVP_MD *md = NULL;
    const iasp_pkey_t *pkeybin;

    assert(id != NULL);

    /* get md for profile */
    md = EVP_get_digestbynid(spn_map[id->spn].nid_dgst);

    /* reset pkey */
    memset(&sign_pkey, 0, sizeof(sign_pkey));

    /* setup pkey */
    switch(sigtype) {
        case IASP_SIG_EC:
            /* set pkey type */
            EVP_PKEY_set_type(&sign_pkey, EVP_PKEY_EC);

            /* find public key */
            pkeybin = security_get_pkey_by_id(id);
            if(pkeybin == NULL) {
                return false;
            }

            /* initiate EVP_PKEY */
            if(!crypto_pkey_to_evp(pkeybin, &sign_pkey)) {
                return false;
            }
            break;

        case IASP_SIG_HMAC:
            if(oob == NULL) {
                return false;
            }

            /* correct key length */
            if(md->md_size < oob->size) {
                sign_key.length = md->md_size;
            }

            EVP_PKEY_set_type(&sign_pkey, EVP_PKEY_HMAC);
            EVP_PKEY_assign(&sign_pkey, EVP_PKEY_HMAC, &sign_key);
            break;

        default:
            abort();
    }

    /* init md context */
    EVP_MD_CTX_init(&sign_ctx);

    /* init digest */
    EVP_DigestInit_ex(&sign_ctx, md, NULL);

    /* init verify */
    EVP_DigestVerifyInit(&sign_ctx, NULL, md, NULL, &sign_pkey);
    sign_spn = id->spn;

    return true;
}


bool crypto_verify_update(const unsigned char *b, size_t blen)
{
    debug_log("Adding data to sign verification: ");
    debug_print_binary(b, blen);
    debug_newline();
    return EVP_DigestVerifyUpdate(&sign_ctx, b, blen) != 0;
}


bool crypto_verify_final(const iasp_sig_t * const sig)
{
    ECDSA_SIG* ecdsa;
    size_t dlen;
    size_t siglen;
    const unsigned char *bin = NULL;

    assert(sig != NULL);
    if(sig->spn != sign_spn) {
        return false;
    }

    /* prepare signature */
    switch(sign_type) {
        case IASP_SIG_EC:
            /* get ECDSA structure */
            ecdsa = ECDSA_SIG_new();
            dlen = spn_map[sign_spn].eclen;
            BN_bin2bn(sig->sigdata, dlen, ecdsa->r);
            BN_bin2bn(&sig->sigdata[dlen], dlen, ecdsa->s);
            siglen = i2d_ECDSA_SIG(ecdsa, (unsigned char **)&bin);
            if(siglen == 0) {
                return false;
            }
            break;

        case IASP_SIG_HMAC:
            bin = sig->sigdata;
            siglen = sig->siglen;
            break;

        default:
            abort();
    }

    /* verify signature */
    return EVP_DigestVerifyFinal(&sign_ctx, bin, siglen) != 0;
}


bool crypto_ecdhe_genkey(iasp_spn_code_t spn_code, iasp_pkey_t *pkey, crypto_ecdhe_context_t *ecdhe_ctx)
{
    EC_KEY *eckey;

    /* generate ephemeral key */
    eckey = EC_KEY_new_by_curve_name(spn_map[spn_code].nid_ec);
    assert(eckey != NULL);
    if(EC_KEY_generate_key(eckey) != 1) {
        return false;
    }

    /* save used SPN */
    ecdhe_ctx->spn = spn_code;

    /* store private key */
    if(ecdhe_ctx != NULL) {
        ecdhe_ctx->ctx = eckey;
    }

    /* store public key */
    if(pkey != NULL) {
        if(!crypto_ecdhe_pkey(ecdhe_ctx, pkey)) {
            abort();
        }
    }
    return true;
}


bool crypto_ecdhe_pkey(const crypto_ecdhe_context_t *ecdhe_ctx, iasp_pkey_t * const pkey)
{
    size_t pubkeylen;
    unsigned char *pubkeybuf;

    assert(ecdhe_ctx != NULL);
    assert(ecdhe_ctx->ctx != NULL);

    /* setup SPN */
    pkey->spn = ecdhe_ctx->spn;

    /* extract key from EC_KEY */
    pubkeylen = spn_map[ecdhe_ctx->spn].eclen + 1;
    pubkeybuf = pkey->pkeydata;
    if(!crypto_get_public_key((EC_KEY *)ecdhe_ctx->ctx, POINT_CONVERSION_COMPRESSED, &pubkeybuf, &pubkeylen)) {
        return false;
    }
    pkey->pkeylen = pubkeylen;

    return true;
}


bool crypto_ecdhe_compute_secret(const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx,
        uint8_t *secret, size_t secretlen, const binbuf_t * const salt)
{
    EC_KEY *own_key;
    EC_POINT *ecpoint;
    const EC_GROUP *group;
    static uint8_t *secretbuf;
    size_t eclen = spn_map[pkey->spn].eclen;

    /* allocate secret buffer */
    secretbuf = malloc(eclen);
    memset(secretbuf, 0, eclen);

    /* determine private key */
    if(ecdhe_ctx == NULL || ecdhe_ctx->ctx == NULL) {
        debug_log("Using own key for ECDHE\n");
        const iasp_spn_support_t *cs = crypto_get_supported_spn(pkey->spn);
        own_key = (EC_KEY *)cs->aux_data;
    }
    else {
        debug_log("Using ephemeral key as own for ECDHE\n");
        own_key = (EC_KEY *)ecdhe_ctx->ctx;
    }

    /* setup public key */
    debug_log("Using public key for ECDHE: ");
    debug_print_pkey(pkey);
    debug_newline();
    group = EC_GROUP_new_by_curve_name(spn_map[pkey->spn].nid_ec);
    ecpoint = EC_POINT_new(group);
    if(EC_POINT_oct2point(group, ecpoint, pkey->pkeydata, pkey->pkeylen, NULL) == 0) {
        return false;
    }

    /* compute secret */
    if(ECDH_compute_key(secretbuf, eclen, ecpoint, own_key, NULL) == 0) {
        return false;
    }

    /* derive secret */
    return spn_map[pkey->spn].kdf(secretbuf, eclen, secret, &secretlen, salt) != NULL;
}


static void *kdf_spn1(const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const salt)
{
    const EVP_MD *md =  EVP_get_digestbynid(spn_map[IASP_SPN_128].nid_dgst);
    return kdf_common(md, in, inlen, out, outlen, salt);
}


static void *kdf_spn2(const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const salt)
{
    const EVP_MD *md =  EVP_get_digestbynid(spn_map[IASP_SPN_256].nid_dgst);
    return kdf_common(md, in, inlen, out, outlen, salt);
}


static void *kdf_common(const EVP_MD *md, const void *in, size_t inlen, void *out, size_t *outlen, const binbuf_t * const salt)
{
    HMAC_CTX ctx;
    unsigned char *tblock;
    unsigned char *obuf = out;
    uint8_t *cnt;
    unsigned hmac_len;
    size_t generated;
    size_t tblocklen;

    debug_log("Using SALT for ECDHE: ");
    debug_print_binary(salt->buf, salt->size);
    debug_newline();

    /* allocate and reset tblock */
    tblocklen = md->md_size + salt->size + sizeof(*cnt);
    tblock = malloc(tblocklen);
    memset(tblock, 0, md->md_size + salt->size);
    memcpy(tblock + salt->size, salt->buf, salt->size);
    cnt = &tblock[md->md_size + salt->size];

    /* generate T(0) */
    *cnt = 0x01;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, in, inlen, md, NULL);
    HMAC_Update(&ctx, salt->buf, salt->size);
    HMAC_Update(&ctx, cnt, 1);
    HMAC_Final(&ctx, tblock, &hmac_len);
    generated = md->md_size;

    /* generate T(1) .. T(N) */
    for(;;) {
        if(generated < *outlen) {
            memcpy(obuf, tblock, md->md_size);
            obuf += md->md_size;
        }
        else {
            if(generated == *outlen) {
                memcpy(obuf, tblock, md->md_size);
            }
            else {
                memcpy(obuf, tblock, *outlen % md->md_size);
            }

            free(tblock);
            return out;
        }

        *cnt = *cnt + 1;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, in, inlen, md, NULL);
        HMAC_Update(&ctx, tblock, tblocklen);
        HMAC_Final(&ctx, tblock, &hmac_len);
        generated += md->md_size;
    }

    /* never reached */
    return NULL;
}


void crypto_openssl_set_oob_key(const binbuf_t * const bb)
{
    oob = bb;
    sign_key.data = oob->buf;
    sign_key.flags = 0;
    sign_key.length = oob->size;
    sign_key.type = V_ASN1_OCTET_STRING;
}


void crypto_destroy()
{
    iasp_spn_support_t *s = spn;

    while(s != NULL) {
        EC_KEY *eckey;
        iasp_spn_support_t *next = s->next;

        eckey = (EC_KEY *)s->aux_data;

        if(eckey) {
            EC_KEY_free(eckey);
        }

        free(s);
        s = next;
    }

    /* keys cleanup */

    /* general openssl cleanup */
    ENGINE_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();
}


bool crypto_get_pkey(iasp_spn_code_t spn_code, iasp_pkey_t * const pkey)
{
    const iasp_spn_support_t *s = crypto_get_supported_spn(spn_code);
    EC_KEY *eckey;
    uint8_t *buf;
    size_t bufsize;

    assert(pkey != NULL);

    if(s == NULL) {
        return false;
    }
    eckey = (EC_KEY *)s->aux_data;

    /* get public key */
    buf = pkey->pkeydata;
    bufsize = spn_get_pkey_length(spn_code, true);
    if(!crypto_get_public_key(eckey, POINT_CONVERSION_COMPRESSED, &buf, &bufsize)) {
        return false;
    }

    /* set pkey data */
    pkey->spn = spn_code;
    pkey->pkeylen = bufsize;

    return true;

}


bool crypto_gen_key(iasp_spn_code_t spn, iasp_key_t *const key)
{
    key->keysize = spn_map[spn].keysize;
    key->spn = spn;

    return RAND_bytes(key->keydata, key->keysize) == 1;
}


bool crypto_gen_salt(iasp_salt_t * const salt)
{
    assert(salt != NULL);
    return RAND_bytes(salt->saltdata, sizeof(salt->saltdata)) == 1;
}


bool crypto_encrypt(iasp_spn_code_t spn, binbuf_t * const p, const binbuf_t * const a, binbuf_t * const n,
        const uint8_t * const k, binbuf_t *c)
{
    EVP_CIPHER_CTX *ctx;
    int outl;

    /* context init */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return false;
    }

    /* set CCM algo with SPN */
    if(EVP_EncryptInit_ex(ctx, spn_map[spn].ccm(), NULL, NULL, NULL) != 1) {
        return false;
    }

    /* set IV len */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, n->size, NULL) != 1) {
        return false;
    }

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, IASP_CRYPTO_TAG_LENGTH, NULL);

    /* init key and iv */
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, k, n->buf) != 1) {
        return false;
    }

    /* set plaintext length */
    if(EVP_EncryptUpdate(ctx, NULL, &outl, NULL, p->size) != 1) {
        return false;
    }

    /* set AAD data */
    if(a != NULL && a->buf != NULL && a->size > 0) {
        if(EVP_EncryptUpdate(ctx, NULL, &outl, a->buf, a->size) != 1) {
            return false;
        }
    }

    /* encrypt message */
    if(EVP_EncryptUpdate(ctx, c->buf, &outl, p->buf, p->size) != 1) {
        return false;
    }
    c->size = outl;

    /* finalize encryption */
    if(EVP_EncryptFinal_ex(ctx, c->buf + c->size, &outl) != 1) {
        return false;
    }
    c->size += outl;

    /* get tag */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, IASP_CRYPTO_TAG_LENGTH, c->buf + c->size) != 1) {
        return false;
    }
    c->size += IASP_CRYPTO_TAG_LENGTH;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return true;
}


bool crypto_decrypt(iasp_spn_code_t spn, binbuf_t * const p, const binbuf_t * const a, binbuf_t * const n,
        const uint8_t * const k, binbuf_t *c)
{
    EVP_CIPHER_CTX *ctx;
    int outl;

    /* init context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return false;
    }

    /* set CCM algo with SPN */
    if(EVP_DecryptInit_ex(ctx, spn_map[spn].ccm(), NULL, NULL, NULL) != 1) {
        return false;
    }

    /* set IV */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, n->size, NULL) != 1) {
        return false;
    }

    /* set expected tag value. */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, IASP_CRYPTO_TAG_LENGTH, c->buf + c->size - IASP_CRYPTO_TAG_LENGTH) != 1) {
        return false;
    }

    /* set key and IV */
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, k, n->buf) != 1) {
        return false;
    }

    /* set ciphertext length */
    if(EVP_DecryptUpdate(ctx, NULL, &outl, NULL, c->size - IASP_CRYPTO_TAG_LENGTH) != 1) {
        return false;
    }

    /* set AAD data */
    if(a != NULL && a->buf != NULL && a->size > 0) {
        if(EVP_DecryptUpdate(ctx, NULL, &outl, a->buf, a->size) != 1) {
            return false;
        }
    }

    /* decrypt, get plaintext */
    if(EVP_DecryptUpdate(ctx, p->buf, &outl, c->buf, c->size - IASP_CRYPTO_TAG_LENGTH) <= 0) {
        return false;
    }
    p->size = outl;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return true;
}
