#include "streambuf.h"
#include "binbuf.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>


void streambuf_init(streambuf_t *this, uint8_t *buf, size_t size, size_t max_size)
{
    assert(this != NULL);
    assert(max_size > 0);
    assert(max_size >= size);

    memset(this, 0, sizeof(streambuf_t));

    this->data = buf;
    this->size = size;
    this->max_size = max_size;
    this->read_index = 0;
}


bool streambuf_read(streambuf_t *this, uint8_t *buf, size_t readsize)
{
    assert(this != NULL);
    assert(buf != NULL);

    if(readsize == 0 || this->size - this->read_index < readsize) {
        return false;
    }

    memcpy(buf, this->data + this->read_index, readsize);
    this->read_index += readsize;

    return true;
}


bool streambuf_write(streambuf_t *this, const uint8_t *buf, size_t writesize)
{
    if(writesize == 0 || this->max_size - this->size < writesize) {
        return false;
    }

    memcpy(this->data + this->size, buf, writesize);
    this->size += writesize;

    return true;
}


void streambuf_reset_input(streambuf_t *this)
{
    assert(this != NULL);

    this->read_index = 0;
}


void streambuf_reset_output(streambuf_t *this)
{
    assert(this != NULL);

    this->size = 0;
    memset(this->data, 0, this->max_size);
}


bool streambuf_write_sb(streambuf_t *this, streambuf_t *that)
{
    assert(this != NULL);
    assert(that != NULL);

    if(that->size > this->max_size - this->size) {
        return false;
    }

    memcpy(&this->data[this->size], that->data, that->size);
    this->size += that->size;

    return true;
}


void streambuf_reset(streambuf_t *this)
{
    assert(this != NULL);

    streambuf_reset_input(this);
    streambuf_reset_output(this);
}


/* INFO: thread unsafe */
const binbuf_t *streambuf_to_bb(const streambuf_t * const this)
{
    static binbuf_t bb;

    bb.buf = this->data;
    bb.size = this->size;

    return &bb;
}
