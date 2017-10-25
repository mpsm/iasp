#ifndef __IASP_ENCODE_H__
#define __IASP_ENCODE_H__

#include "types.h"
#include "streambuf.h"
#include "field.h"
#include "message.h"

#include <stdbool.h>


/* general encoding */
bool iasp_encode_varint(streambuf_t *sb, unsigned int i);
bool iasp_encode_field_code(streambuf_t *sb, iasp_field_code_t field_code);

/* field encodind */
bool iasp_encode_id(streambuf_t *sb, iasp_spn_code_t spn, const iasp_identity_t *id);
bool iasp_encode_ids(streambuf_t *sb, const iasp_spn_support_t *spns);
bool iasp_encode_spn(streambuf_t *sb, iasp_spn_code_t spn);
bool iasp_encode_setof(streambuf_t *sb, iasp_field_code_t field_code, unsigned int count);
bool iasp_encode_nonce(streambuf_t *sb, const iasp_nonce_t *nonce);

/* message encoding */
bool iasp_encode_hmsg_init_hello(streambuf_t *sb, const iasp_spn_support_t *spns);
bool iasp_encode_hmsg_resp_hello(streambuf_t *sb, iasp_spn_code_t spn, const iasp_identity_t *id,
        const iasp_nonce_t *nonce);

#endif
