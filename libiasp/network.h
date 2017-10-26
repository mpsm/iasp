#ifndef __IASP_NETWORK_H__
#define __IASP_NETWORK_H__

#include "types.h"
#include "binbuf.h"

#include <stdbool.h>
#include <stdint.h>


typedef struct {
    iasp_ip_t ip;
    uint16_t port;
    void *aux;
} iasp_peer_t;


bool iasp_network_send(const iasp_peer_t * const peer, const binbuf_t * const msg);
bool iasp_network_receive(iasp_peer_t * const peer, binbuf_t * const msg);


#endif
