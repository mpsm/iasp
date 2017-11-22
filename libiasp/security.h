#ifndef __IASP_SECURITY_H__
#define __IASP_SECURITY_H__

#include "types.h"
#include "binbuf.h"
#include "spn.h"

#include <stdbool.h>


/* init */
void security_init(void);

/* key management */
bool security_add_pkey(iasp_pkey_t *pkey, bool privileged);
bool security_add_pkey_dup(iasp_pkey_t *pkey, bool privileged);
const iasp_pkey_t *security_get_pkey_by_id(const iasp_identity_t * const id);

/* SPN policy */
iasp_spn_code_t security_choose_spn(const iasp_ids_t * const ids);
iasp_spn_code_t security_choose_spn2(const iasp_ids_t * const iids, const iasp_ids_t * const rids);

/* weak authorization methods */
bool security_use_hint(const iasp_hint_t * const hint);
bool security_authorize_peer(const iasp_pkey_t *pkey);


#endif
