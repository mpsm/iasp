#ifndef __IASP_NETWORK_H__
#define __IASP_NETWORK_H__

#include "types.h"
#include "binbuf.h"

#include <stdbool.h>
#include <stdint.h>


typedef struct {
    void *aux;
} iasp_address_t;


/* network methods */
bool iasp_network_add_address(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port);
bool iasp_network_release_address(iasp_address_t * const address);
bool iasp_network_send(const iasp_address_t * const address, const iasp_address_t * const peer, const binbuf_t * const msg);
bool iasp_network_receive(const iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg);

/* address related methods */
void iasp_network_address2ip(const iasp_address_t * const address, iasp_ip_t * const ip);
void iasp_network_address_init(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port);
void iasp_network_address_destroy(iasp_address_t * const address);


#endif
