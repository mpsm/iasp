#ifndef __IASP_SPN_H__
#define __IASP_SPN_H__

#include "types.h"

#include <stdbool.h>

/* SPN info */
size_t spn_get_key_size(iasp_spn_code_t spn);
size_t spn_get_sign_length(iasp_spn_code_t spn_code, iasp_sigtype_t sigtype);
size_t spn_get_pkey_length(iasp_spn_code_t spn, bool compressed);

#endif
