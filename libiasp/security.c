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


const iasp_identity_t * security_id_by_spn(iasp_spn_code_t spn, const iasp_ids_t * const ids)
{
    unsigned int i;

    assert(ids != NULL);

    for(i = 0; i < ids->id_count; ++i) {
        if(ids->id[i].spn == spn) {
            return &ids->id[i];
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
