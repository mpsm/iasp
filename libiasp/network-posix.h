#ifndef __NETWORK_POSIX_H__
#define __NETWORK_POSIX_H__

#include "types.h"

#include <stdbool.h>
#include <stdint.h>

/* add release my own address */
bool network_posix_add_address(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port);
bool network_posix_add_address_str(iasp_address_t * const address, const char *ip, const uint16_t port);
bool network_posix_release_address(iasp_address_t * const address);

/* init address and ip from string */
bool network_posix_address_init_str(iasp_address_t * const address, const char *ip, const uint16_t port);
bool network_posix_ip_from_str(iasp_ip_t * const ip, const char *str);

/* string conversion methods */
const char *network_posix_ip_to_str(const iasp_ip_t * const ip);
bool network_posix_ip_from_str(iasp_ip_t * const ip, const char *str);

#endif
