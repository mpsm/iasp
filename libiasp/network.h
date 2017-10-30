#ifndef __IASP_NETWORK_H__
#define __IASP_NETWORK_H__

#include "types.h"
#include "binbuf.h"

#include <stdbool.h>
#include <stdint.h>

#define IASP_NET_STR_IP(x) (iasp_network_ip_to_str(iasp_network_address_ip(x)))


typedef struct {
    void *aux;
} iasp_address_t;


/* network methods */
bool iasp_network_add_address(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port);
bool iasp_network_add_address_str(iasp_address_t * const address, const char *ip, const uint16_t port);
bool iasp_network_release_address(iasp_address_t * const address);
bool iasp_network_send(const iasp_address_t * const address, const iasp_address_t * const peer, const binbuf_t * const msg);
bool iasp_network_receive(const iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg);

/* address related methods */
void iasp_network_address2ip(const iasp_address_t * const address, iasp_ip_t * const ip);
void iasp_network_address_init(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port);
bool iasp_network_address_init_str(iasp_address_t * const address, const char *ip, const uint16_t port);
void iasp_network_address_destroy(iasp_address_t * const address);
const iasp_ip_t *iasp_network_address_ip(const iasp_address_t * const address);
uint16_t iasp_network_address_port(const iasp_address_t * const address);

/* ip related methods */
bool iasp_network_ip_from_str(iasp_ip_t * const ip, const char *str);
const char *iasp_network_ip_to_str(const iasp_ip_t * const ip);

#endif
