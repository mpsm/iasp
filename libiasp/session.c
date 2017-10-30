#include "session.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


/* TODO: move buffer */
#define SESSION_BUFFER_SIZE (128)
static uint8_t session_buffer[SESSION_BUFFER_SIZE];


void iasp_session_init(iasp_session_t * const this, const iasp_address_t *addr, const iasp_address_t *peer_addr)
{
    assert(addr != NULL);
    assert(peer_addr != NULL);

    memset(this, 0, sizeof(iasp_session_t));

#if 0
    //this->encrypted = false;
    this->pn = 0;
    this->pv = IASP_PV_0;
    this->spn = IASP_SPN_NONE;
#endif

    this->my_addr = addr;
    this->peer_addr = peer_addr;
}


void iasp_session_start(iasp_session_t * const this)
{
    uint8_t *buf = session_buffer;

    this->pn = 0;
    this->pv = IASP_PV_0;
    this->spn = IASP_SPN_NONE;

    /* put outer header */
    iasp_proto_put_outer_hdr(buf, false, this->pv, IASP_SPN_NONE);
    buf++;

    iasp_proto_put_inner_hdr(buf, IASP_MSG_HANDSHAKE, false, 0);

}
