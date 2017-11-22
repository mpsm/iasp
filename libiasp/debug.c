#if defined(IASP_DEBUG) && IASP_DEBUG == 1

#include "debug.h"
#include "types.h"
#include "network.h"
#include "session.h"

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>


/* private methods */
static const char *debug_side2str(iasp_session_side_t side);


void debug_log(const char *fmt, ...)
{
    va_list va;
    time_t ltime;
    struct tm *ltime_tm;

    time(&ltime);
    ltime_tm = localtime(&ltime);

    printf("[%.*s] ", 15, asctime(ltime_tm) + 4);

    va_start(va, fmt);
    vprintf(fmt, va);
    va_end(va);
}


void debug_print_binary(const uint8_t *data, size_t size)
{
    unsigned int i;

    for(i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
}

void debug_print_nonce(const iasp_nonce_t *nonce)
{
    debug_print_binary(nonce->data, sizeof(nonce->data));
}



void debug_print_spn(const iasp_spn_code_t spn)
{
    static const char *spn_str[IASP_SPN_MAX] = {
            "none",
            "SPN 1 / 128 bits",
            "SPN 2 / 256 bits",
    };

    printf("%s", spn_str[spn]);
}

void debug_print_id(const iasp_identity_t *id)
{
    debug_print_spn(id->spn);
    printf(", ID: ");
    debug_print_binary(id->data, sizeof(id->data));
}


void debug_newline(void)
{
    printf("\n");
}


void debug_print_pkey(const iasp_pkey_t *pkey)
{
    debug_print_spn(pkey->spn);
    printf(" | %lu bytes | ", pkey->pkeylen);
    debug_print_binary(pkey->pkeydata, pkey->pkeylen);
}


void debug_print_address(const iasp_address_t *addr)
{
    iasp_ip_t ip;

    iasp_network_address2ip(addr, &ip);

    printf("%s:%d", iasp_network_ip_to_str(&ip), iasp_network_address_port(addr));
}


static const char *debug_side2str(iasp_session_side_t side)
{
    switch(side) {
        case SESSION_SIDE_INITIATOR:
            return "initiator";

        case SESSION_SIDE_RESPONDER:
            return "responder";

        default:
            return "!invalid!";
    }
}


void debug_print_session(const iasp_session_t * const s)
{
    unsigned int i;

    printf("Session %p (%s) ", s, s->active ? "active" : "inactive");
    debug_print_spn(s->spn);
    printf(": \n");
    debug_print_address(&s->pctx.addr);
    printf(" <-> ");
    debug_print_address(&s->pctx.peer);
    debug_newline();
    printf("  side: %s\n", debug_side2str(s->side));
    printf("  SALT: ");
    debug_print_binary(s->salt.saltdata, sizeof(s->salt.saltdata));
    debug_newline();

    for(i = 0; i < SESSION_SIDE_COUNT; ++i) {
        printf("  %s data: \n", debug_side2str(i));
        printf("    id:    ");
        debug_print_id(&s->sides[i].id); debug_newline();
        printf("    key:   ");
        debug_print_key(&s->sides[i].key); debug_newline();
        printf("    nonce: ");
        debug_print_nonce(&s->sides[i].nonce); debug_newline();
        printf("    spi:   ");
        debug_print_spi(&s->sides[i].spi); debug_newline();
        printf("    flags: %02x\n", s->sides[i].flags.byte);
    }
}


void debug_print_key(const iasp_key_t * const key)
{
    if(key->spn == IASP_SPN_NONE) {
        printf("none");
        return;
    }

    debug_print_spn(key->spn);
    printf(" | length: %lu | ", key->keysize);
    debug_print_binary(key->keydata, key->keysize);
}


void debug_print_spi(const iasp_spi_t * const spi)
{
    debug_print_binary(spi->spidata, sizeof(spi->spidata));
}

#endif
