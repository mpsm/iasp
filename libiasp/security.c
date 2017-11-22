#include "config.h"

#include "types.h"
#include "security.h"
#include "binbuf.h"
#include "crypto.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


#ifndef IASP_CONFIG_SECURITY_MAX_PKEYS
#  define IASP_CONFIG_SECURITY_MAX_PKEYS (10)
#endif


struct security_pkey_data {
    iasp_pkey_t *pkey;
    bool privileged;
    iasp_identity_t id;
}
security_pkeys[IASP_CONFIG_SECURITY_MAX_PKEYS];
size_t security_pkeys_count;


void security_init()
{
    memset(security_pkeys, 0, sizeof(security_pkeys));
    security_pkeys_count = 0;
}


bool security_add_pkey_dup(iasp_pkey_t *pkey, bool privileged)
{
    iasp_pkey_t *dup;

    assert(pkey != NULL);

    dup = malloc(sizeof(iasp_pkey_t));
    memcpy(dup, pkey, sizeof(iasp_pkey_t));

    return security_add_pkey(dup, privileged);
}


bool security_add_pkey(iasp_pkey_t *pkey, bool privileged)
{
    struct security_pkey_data *spd;

    assert(pkey != NULL);

    if(security_pkeys_count == IASP_CONFIG_SECURITY_MAX_PKEYS) {
        return false;
    }

    /* fill data */
    spd = &security_pkeys[security_pkeys_count];
    spd->privileged = privileged;
    spd->pkey = pkey;
    if(!crypto_get_pkey_id(spd->pkey, &spd->id)) {
        return false;
    }

    /* update key count */
    security_pkeys_count++;

    return true;
}


const iasp_pkey_t *security_get_pkey_by_id(const iasp_identity_t * const id)
{
    unsigned int i;

    for(i = 0; i < security_pkeys_count; ++i) {
        if(memcmp(id, &security_pkeys[i].id, sizeof(iasp_identity_t)) == 0) {
            return security_pkeys[i].pkey;
        }
    }

    return NULL;
}


__attribute__((weak)) bool security_use_hint(const iasp_hint_t * const hint)
{
    return true;
}


__attribute__((weak)) bool security_authorize_peer(const iasp_pkey_t *pkey)
{
    return true;
}
