#include "streambuf.h"


#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>


void streambuf_init(streambuf_t *this, uint8_t *buf, size_t size)
{
    assert(this != NULL);
    assert(size > 0);

    memset(this, 0, sizeof(streambuf_t));

    this->data = buf;
    this->size = size;
    this->index = 0;
}


size_t streambuf_read(streambuf_t *this, uint8_t *buf, size_t readsize)
{
    size_t to_read;

    assert(this != NULL);
    assert(buf != NULL);

    if(readsize == 0) {
        return 0;
    }

    to_read = this->index + readsize < this->size ? readsize : this->size - this->index - readsize;

    memcpy(buf, this->data, to_read);
    this->index += to_read;

    return to_read;
}
