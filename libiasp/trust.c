#include "trust.h"
#include "types.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>


/* private data */
const iasp_identity_t *tpid = NULL;


void iasp_trust_set_tp(const iasp_identity_t* const id)
{
    tpid = id;
}


bool iasp_trust_is_trusted_tp(const iasp_identity_t * const id)
{
    if(tpid == NULL) {
        return false;
    }

    return tpid->spn == id->spn && (memcmp(tpid->data, id->data, sizeof(id->data)) == 0);
}


bool iasp_trust_is_trusted_peer(const iasp_identity_t * const id)
{
    /* TODO */
    return false;
}
