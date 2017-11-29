#ifndef __IASP_ADDRESS_H__
#define __IASP_ADDRESS_H__

#include "types.h"

#include <stdbool.h>
#include <stdint.h>


/* address related methods */
void iasp_network_address_init(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port);
void iasp_network_address_destroy(iasp_address_t * const address);
const iasp_ip_t *iasp_network_address_ip(const iasp_address_t * const address);
uint16_t iasp_network_address_port(const iasp_address_t * const address);
bool iasp_network_address_equal(const iasp_address_t * const left, const iasp_address_t * const right);
void iasp_network_address_dup(const iasp_address_t * const address, iasp_address_t *new);


#endif
