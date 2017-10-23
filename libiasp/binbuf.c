#include "binbuf.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>


void binbuf_init(binbuf_t * const this, uint8_t *buf, size_t size)
{
    assert(this != NULL);
    assert(buf != NULL);
    assert(size > 0);

    this->buf = buf;
    this->size = size;
}
