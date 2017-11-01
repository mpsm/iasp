#ifndef __IASP_H__
#define __IASP_H__

#include "types.h"

#include <stdint.h>
#include <stddef.h>

#define IASP_DEFAULT_PORT (35491)


void iasp_init(iasp_role_t role, uint8_t *buf, size_t bufsize);
iasp_role_t iasp_get_role(void);

#endif
