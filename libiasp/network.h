#ifndef __IASP_NETWORK_H__
#define __IASP_NETWORK_H__

#include "types.h"
#include "binbuf.h"

#include <stdbool.h>


/* send/receive methods */
bool iasp_network_send(const iasp_address_t * const address, const iasp_address_t * const peer, const binbuf_t * const msg);
bool iasp_network_receive(iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg,
        unsigned int timeout);
bool iasp_network_receive_any(iasp_address_t * const address,  iasp_address_t * const peer, binbuf_t * const msg,
        unsigned int timeout);


#endif
