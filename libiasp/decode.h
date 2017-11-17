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
bool iasp_decode_id(streambuf_t *sb, iasp_identity_t * const id, bool raw);
bool iasp_decode_ids(streambuf_t *sb, iasp_ids_t *ids);
bool iasp_decode_spn(streambuf_t *sb, iasp_spn_code_t *spn);
bool iasp_decode_setof(streambuf_t *sb, iasp_field_code_t field_code, unsigned int *count);
bool iasp_decode_nonce(streambuf_t *sb, iasp_nonce_t * const nonce);
bool iasp_decode_sig(streambuf_t *sb, iasp_sig_t * const sig);
bool iasp_decode_pkey(streambuf_t *sb, iasp_pkey_t * const pkey);
bool iasp_decode_dhkey(streambuf_t *sb, iasp_pkey_t * const pkey);
bool iasp_decode_sigtype(streambuf_t *sb, iasp_sigtype_t * const sigtype, bool raw);
bool iasp_decode_session_flags(streambuf_t *sb, iasp_session_flags_t * const flags);
bool iasp_decode_hint(streambuf_t *sb, iasp_hint_t * const hint);
bool iasp_decode_address(streambuf_t *sb, iasp_address_t * const address);
bool iasp_decode_spi(streambuf_t *sb, iasp_spi_t * const spi);

/* message decoding */
bool iasp_decode_hmsg_init_hello(streambuf_t *sb, iasp_hmsg_init_hello_t * const msg);
bool iasp_decode_hmsg_resp_hello(streambuf_t *sb, iasp_hmsg_resp_hello_t * const msg);
bool iasp_decode_hmsg_init_auth(streambuf_t *sb, iasp_hmsg_init_auth_t * const msg);
bool iasp_decode_hmsg_resp_auth(streambuf_t *sb, iasp_hmsg_resp_auth_t * const msg);
bool iasp_decode_hmsg_redirect(streambuf_t *sb, iasp_hmsg_redirect_t * const msg);
bool iasp_decode_mgmt_req_session(streambuf_t *sb, iasp_mgmt_req_session_t * const msg);
bool iasp_decode_mgmt_install_session(streambuf_t *sb, iasp_mgmt_install_session_t * const msg);

#endif
