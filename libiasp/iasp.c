#include "iasp.h"
#include "proto.h"
#include "crypto.h"
#include "session.h"
#include "types.h"


static iasp_role_t iasp_role;


void iasp_init(iasp_role_t role, uint8_t *buf, size_t bufsize)
{
    crypto_init();
    iasp_proto_init(buf, bufsize);
    iasp_role = role;
    iasp_session_set_role(role);
    iasp_sessions_reset();
}


iasp_role_t iasp_get_role()
{
    return iasp_role;
}
