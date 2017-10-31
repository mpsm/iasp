#ifndef __IASP_H__
#define __IASP_H__

#include <stdint.h>
#include <stddef.h>

#define IASP_DEFAULT_PORT (35491)

void iasp_init(uint8_t *buf, size_t bufsize);

#endif
