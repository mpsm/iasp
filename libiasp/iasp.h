#ifndef __IASP_H__
#define __IASP_H__

#include "types.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define IASP_DEFAULT_PORT (35491)
#define IASP_CRYPTO_TAG_LENGTH (4)


void iasp_init(iasp_role_t role, uint8_t *buf, size_t bufsize);

/* set/get hint */
void iasp_set_hint(const char *s);
bool iasp_get_hint(iasp_hint_t *h);

/* get my role */
iasp_role_t iasp_get_role(void);

/* get/set TP addres */
void iasp_set_tpaddr(const iasp_address_t *const tpaddr);
const iasp_address_t * iasp_get_tpaddr(void);

#endif
