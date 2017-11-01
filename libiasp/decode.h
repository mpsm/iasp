#ifndef __IASP_DECODE_H__
#define __IASP_DECODE_H__

#include "streambuf.h"
#include "types.h"
#include "field.h"
#include "message.h"

#include <stdbool.h>


/* general decoding */
bool iasp_decode_varint(streambuf_t *sb, unsigned int *i);
bool iasp_decode_field_code(streambuf_t *sb, iasp_field_code_t *field_code);
bool iasp_decode_hmsg_code(streambuf_t *sb, iasp_handshake_msg_code_t *hmsg_code);

/* field decoding */
bool iasp_decode_id(streambuf_t *sb, iasp_identity_t * const id);
bool iasp_decode_ids(streambuf_t *sb, iasp_ids_t *ids);
bool iasp_decode_spn(streambuf_t *sb, iasp_spn_code_t *spn);
bool iasp_decode_setof(streambuf_t *sb, iasp_field_code_t field_code, unsigned int *count);
bool iasp_decode_nonce(streambuf_t *sb, iasp_nonce_t * const nonce);

/* message decoding */
bool iasp_decode_hmsg_init_hello(streambuf_t *sb, iasp_hmsg_init_hello_t * const msg);
bool iasp_decode_hmsg_resp_hello(streambuf_t *sb, iasp_hmsg_resp_hello_t * const msg);


#endif
