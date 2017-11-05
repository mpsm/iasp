#if defined(IASP_DEBUG) && IASP_DEBUG == 1

#include "debug.h"
#include "types.h"

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>


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
    printf("NONCE: ");
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

#endif
