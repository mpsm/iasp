#ifndef __IASP_ENCODE_H__
#define __IASP_ENCODE_H__

#include "types.h"
#include "streambuf.h"
#include "field.h"

#include <stdbool.h>

bool iasp_encode_varint(streambuf_t *sb, unsigned int i);
bool iasp_encode_field_code(streambuf_t *sb, iasp_field_code_t field_code);
bool iasp_encode_id(streambuf_t *sb, const iasp_identity_t *id);

#endif
