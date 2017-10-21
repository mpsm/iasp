#ifndef __IASP_FIELD_H__
#define __IASP_FIELD_H__


#include <stdint.h>
#include "streambuf.h"


typedef uint64_t iasp_field_identity_t;


void iasp_encode_identity(streambuf_t *sb, iasp_field_identity_t *id);


#endif
