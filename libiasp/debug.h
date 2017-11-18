#ifndef __IASP_DEBUG_H__
#define __IASP_DEBUG_H__

#include "types.h"
#include "network.h"
#include "session.h"

#include <stdint.h>
#include <stddef.h>

#if !defined(IASP_DEBUG)
#  define IASP_DEBUG (0)
#endif

#if IASP_DEBUG == 1

void debug_log(const char *fmt, ...);
void debug_print_binary(const uint8_t *data, size_t size);
void debug_newline(void);
void debug_print_nonce(const iasp_nonce_t *nonce);
void debug_print_id(const iasp_identity_t *id);
void debug_print_pkey(const iasp_pkey_t *pkey);
void debug_print_address(const iasp_address_t *addr);
void debug_print_spn(const iasp_spn_code_t spn);
void debug_print_session(const iasp_session_t * const s);
void debug_print_key(const iasp_key_t * const key);
void debug_print_spi(const iasp_spi_t * const spi);


#elif IASP_DEBUG == 0

#  define debug_log(X, ...)         {}
#  define debug_print_binary(X,Y)   {}
#  define debug_newline()           {}
#  define debug_print_nonce(X)      {}
#  define debug_print_id(X)         {}
#  define debug_print_pkey(X)       {}
#  define debug_print_address(X)    {}
#  define debug_print_spn(X)        {}
#  define debug_print_session(X)    {}
#  define debug_print_spi(X)        {}
#  define debug_print_key(X)        {}


#else
#  error "Invalid IASP_DEBUG value"
#endif

#endif
