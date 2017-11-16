#include "iasp.h"
#include "binbuf.h"
#include "config.h"
#include "proto.h"
#include "crypto.h"
#include "session.h"
#include "types.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>


static iasp_role_t iasp_role;
static binbuf_t iasp_hint;
static const iasp_address_t *tpaddr;


void iasp_init(iasp_role_t role, uint8_t *buf, size_t bufsize)
{
    crypto_init();
    iasp_proto_init(buf, bufsize);
    iasp_role = role;
    iasp_session_set_role(role);
    iasp_sessions_reset();
    memset(&iasp_hint, 0, sizeof(binbuf_t));
}


iasp_role_t iasp_get_role()
{
    return iasp_role;
}


void iasp_set_hint(const char *s)
{
    assert(s != NULL);

    binbuf_init(&iasp_hint, (uint8_t *)s, strlen(s));
    assert(iasp_hint.size < IASP_CONFIG_MAX_HINT_SIZE);
}


bool iasp_get_hint(iasp_hint_t *h)
{
    assert(h != NULL);

    if(iasp_hint.size == 0) {
        return false;
    }

    h->hintlen = iasp_hint.size;
    memcpy(h->hintdata, iasp_hint.buf, iasp_hint.size);

    return true;
}



void iasp_set_tpaddr(const iasp_address_t *const _tpaddr)
{
    tpaddr = _tpaddr;
}


const iasp_address_t * iasp_get_tpaddr()
{
    return tpaddr;
}

