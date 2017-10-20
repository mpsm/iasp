#ifndef __STREAMBUF_H__
#define __STREAMBUF_H__


#include <stdint.h>
#include <stddef.h>


typedef struct {
    size_t index;
    const uint8_t *data;
    size_t size;
} streambuf_t;


void streambuf_init(streambuf_t *this, uint8_t *buf, size_t size);
size_t streambuf_read(streambuf_t *this, uint8_t *buf, size_t readsize);


#endif
