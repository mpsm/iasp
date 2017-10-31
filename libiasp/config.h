#ifndef __IASP_CONFIG_H__
#define __IASP_CONFIG_H__

#if !defined(IASP_CONFIG_MAX_HINT_LENGTH)
#  define IASP_CONFIG_MAX_HINT_LENGTH (128)
#endif

#if !defined(IASP_CONFIG_IDENTITY_SIZE)
#  define IASP_CONFIG_IDENTITY_SIZE (8)
#endif

#if !defined(IASP_CONFIG_VARINT_MAX_LENGTH)
#  define IASP_CONFIG_VARINT_MAX_LENGTH (4)
#endif

#if !defined(IASP_CONFIG_NONCE_SIZE)
#  define IASP_CONFIG_NONCE_SIZE (4)
#endif

#if !defined(IASP_CONFIG_MAX_PKEY_SIZE)
/* valid for P-521 */
#  define IASP_CONFIG_MAX_PKEY_SIZE (66+1)
#endif

#if !defined(IASP_CONFIG_MAX_SIG_SIZE)
/* valid for P-521 */
#  define IASP_CONFIG_MAX_SIG_SIZE (66*2)
#endif

#if !defined(IASP_CONFIG_MAX_HMAC_SIZE)
/* valid for HMAC SHA-256 */
#  define IASP_CONFIG_MAX_HMAC_SIZE (32)
#endif

#if !defined(IASP_CONFIG_MAX_HINT_SIZE)
#  define IASP_CONFIG_MAX_HINT_SIZE (128)
#endif

#endif
