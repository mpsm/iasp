#ifndef __IASP_PEER_H__
#define __IASP_PEER_H__

#include "types.h"

#include <stdbool.h>

/* add methods */
bool iasp_peer_add(const iasp_identity_t * const id);
bool iasp_peer_add_pkey(const iasp_pkey_t * const pkey);

/* change peer state */
void iasp_peer_blacklist(const iasp_identity_t * const id);
void iasp_peer_privilege(const iasp_identity_t * const id);

/* get state */
bool iasp_peer_is_privileged(const iasp_identity_t * const id);
bool iasp_peer_is_trusted(const iasp_identity_t * const id);
const iasp_pkey_t * iasp_peer_get_pkey(const iasp_identity_t * const id);

#endif
