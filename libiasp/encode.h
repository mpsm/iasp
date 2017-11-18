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
bool iasp_encode_id(streambuf_t *sb, const iasp_identity_t *id);
bool iasp_encode_ids(streambuf_t *sb, const iasp_ids_t *ids);
bool iasp_encode_spn(streambuf_t *sb, iasp_spn_code_t spn, bool raw);
bool iasp_encode_setof(streambuf_t *sb, iasp_field_code_t field_code, unsigned int count);
bool iasp_encode_nonce(streambuf_t *sb, const iasp_nonce_t *nonce);
bool iasp_encode_sig(streambuf_t *sb, const iasp_sig_t *sig);
bool iasp_encode_pkey(streambuf_t *sb, const iasp_pkey_t *pkey);
bool iasp_encode_sigtype(streambuf_t *sb, iasp_sigtype_t sigtype, bool raw);
bool iasp_encode_session_flags(streambuf_t *sb, const iasp_session_flags_t * const flags);
bool iasp_encode_hint(streambuf_t * sb, const iasp_hint_t * const hint);
bool iasp_encode_dhkey(streambuf_t *sb, const iasp_pkey_t *pkey);
bool iasp_encode_address(streambuf_t *sb, const iasp_address_t * const address);
bool iasp_encode_spi(streambuf_t *sb, const iasp_spi_t spi);
bool iasp_encode_skey(streambuf_t *sb, const iasp_skey_t * const skey);

/* message encoding */
bool iasp_encode_hmsg_init_hello(streambuf_t *sb, const iasp_hmsg_init_hello_t * const msg);
bool iasp_encode_hmsg_resp_hello(streambuf_t *sb, const iasp_hmsg_resp_hello_t * const msg);
bool iasp_encode_hmsg_init_auth(streambuf_t *sb, const iasp_hmsg_init_auth_t * const msg);
bool iasp_encode_hmsg_resp_auth(streambuf_t *sb, const iasp_hmsg_resp_auth_t * const msg);
bool iasp_encode_hmsg_redirect(streambuf_t *sb, const iasp_hmsg_redirect_t * const msg);
bool iasp_encode_mgmt_req_session(streambuf_t *sb, const iasp_mgmt_req_session_t * const msg);
bool iasp_encode_mgmt_install_session(streambuf_t *sb, const iasp_mgmt_install_session_t * const msg);
bool iasp_encode_mgmt_spi(streambuf_t *sb, const iasp_mgmt_spi_t * const msg);

#endif
