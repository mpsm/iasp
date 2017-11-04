#ifndef __IASP_DEBUG_H__
#define __IASP_DEBUG_H__

#include "types.h"

#if !defined(IASP_DEBUG)
#  define IASP_DEBUG (0)
#endif

#if IASP_DEBUG == 1

void debug_log(const char *fmt, ...);
void debug_newline(void);
void debug_print_nonce(iasp_nonce_t *nonce);
void debug_print_id(iasp_identity_t *id);


#elif IASP_DEBUG == 0

#  define debug_log(X, ...)     {}
#  define debug_newline()       {}
#  define debug_print_nonce(X)  {}
#  define debug_print_id(X)     {}

#else
#  error "Invalid IASP_DEBUG value"
#endif

#endif
