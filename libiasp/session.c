#include "session.h"

#include <string.h>

void iasp_session_init(iasp_session_t * const this)
{
    memset(this, 0, sizeof(iasp_session_t));

    this->encrypted = false;
    this->pn = 0;
    this->pv = IASP_PV_0;
    this->spn = IASP_SPN_NONE;
}
