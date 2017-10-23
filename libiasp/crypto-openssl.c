#include "crypto.h"
#include "binbuf.h"

#include <openssl/ec.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>


static EC_KEY *my_key;


bool crypto_init(binbuf_t * const pkey)
{
    assert(pkey != NULL);

    if(d2i_ECPrivateKey(&my_key, (const unsigned char **)&pkey->buf, pkey->size) == NULL) {
        return false;
    }

    return true;
}


void crypto_free()
{
    if(my_key != NULL) {
        EC_KEY_free(my_key);
    }
}
