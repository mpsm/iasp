#include "crypto.h"
#include "binbuf.h"

#include <openssl/ec.h>
#include <openssl/objects.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>


static EC_KEY *my_key = NULL;


bool crypto_init(binbuf_t * const pkey)
{
    const EC_GROUP *group;
    int group_nid;

    assert(pkey != NULL);

    if(d2i_ECPrivateKey(&my_key, (const unsigned char **)&pkey->buf, pkey->size) == NULL) {
        return false;
    }

    group = EC_KEY_get0_group(my_key);
    group_nid = EC_GROUP_get_curve_name(group);
    printf("Curve: %s (%d)\n",  OBJ_nid2ln(group_nid), group_nid);

    return true;
}


void crypto_free()
{
    if(my_key != NULL) {
        EC_KEY_free(my_key);
    }
}
