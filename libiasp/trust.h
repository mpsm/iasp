#ifndef __IASP_TRUST_H__
#define __IASP_TRUST_H__

#include "types.h"

#include <stdbool.h>


void iasp_trust_set_tp(const iasp_identity_t* const id);
bool iasp_trust_is_trusted_tp(const iasp_identity_t * const id);
bool iasp_trust_is_trusted_peer(const iasp_identity_t * const id);


#endif
