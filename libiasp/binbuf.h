#ifndef __IASP_BINBUF_H__
#define __IASP_BINBUF_H__

#include <stddef.h>
#include <stdint.h>


typedef struct {
    uint8_t *buf;
    size_t size;
} binbuf_t;

void binbuf_init(binbuf_t * const this, uint8_t * const buf, size_t size);

#endif
