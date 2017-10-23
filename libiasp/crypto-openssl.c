#include "crypto.h"
#include "binbuf.h"
#include "types.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>


/* private constants */
static const struct {
    iasp_spn_code_t spn_code;
    int nid;
} spn_map[] = {
        {IASP_SPN_128, NID_X9_62_prime256v1},
        {IASP_SPN_256, NID_secp521r1},
        {IASP_SPN_MAX, 0},
};

/* private variables */
static EC_KEY *my_key = NULL;
static iasp_spn_code_t spn = IASP_SPN_MAX;
static iasp_identity_t my_id;

/* private methods */
static iasp_identity_t crypto_eckey2id(EC_KEY *key);


bool crypto_init(binbuf_t * const pkey)
{
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    int group_nid;
    int i = 0;

    assert(pkey != NULL);

    if(d2i_ECPrivateKey(&my_key, (const unsigned char **)&pkey->buf, pkey->size) == NULL) {
        return false;
    }

    group = EC_KEY_get0_group(my_key);
    group_nid = EC_GROUP_get_curve_name(group);
    printf("Curve: %s (%d)\n",  OBJ_nid2ln(group_nid), group_nid);

    while(spn_map[i].spn_code != IASP_SPN_MAX) {
        if(spn_map[i].nid == group_nid) {
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

    my_id = crypto_eckey2id(my_key);

    return true;
}


iasp_identity_t crypto_get_id()
{
    return my_id;
}


void crypto_free()
{
    if(my_key != NULL) {
        EC_KEY_free(my_key);
    }
}


static iasp_identity_t crypto_eckey2id(EC_KEY *key)
{
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    uint8_t *buf;
    size_t buflen;

    assert(key != NULL);

    group = EC_KEY_get0_group(my_key);
    pubkey = EC_KEY_get0_public_key(my_key);

    EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);

}
