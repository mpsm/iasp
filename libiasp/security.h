#ifndef __IASP_SECURITY_H__
#define __IASP_SECURITY_H__

#include "types.h"
#include "binbuf.h"
#include "spn.h"

#include <stdbool.h>


/* SPN policy */
iasp_spn_code_t security_choose_spn(const iasp_ids_t * const ids);
iasp_spn_code_t security_choose_spn2(const iasp_ids_t * const iids, const iasp_ids_t * const rids);

/* weak authorization methods */
bool security_use_hint(const iasp_hint_t * const hint);
bool security_authorize_peer(const iasp_pkey_t *pkey);

/* misc */
const iasp_identity_t * security_id_by_spn(iasp_spn_code_t spn, const iasp_ids_t * const ids);


#endif
