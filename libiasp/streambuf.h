#ifndef __STREAMBUF_H__
#define __STREAMBUF_H__

#include "binbuf.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


typedef struct {
    size_t read_index;
    uint8_t *data;
    size_t size;
    size_t max_size;
} streambuf_t;


void streambuf_init(streambuf_t *this, uint8_t *buf, size_t size, size_t max_size);
void streambuf_reset(streambuf_t *this);
void streambuf_reset_input(streambuf_t *this);
void streambuf_reset_output(streambuf_t *this);
bool streambuf_read(streambuf_t *this, uint8_t *buf, size_t readsize);
bool streambuf_write(streambuf_t *this, const uint8_t *buf, size_t writesize);
bool streambuf_write_sb(streambuf_t *this, streambuf_t *that);
const binbuf_t *streambuf_to_bb(const streambuf_t * const this);

#endif
