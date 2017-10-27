#include "network.h"
#include "types.h"
#include "binbuf.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


bool iasp_network_send(const iasp_peer_t * const peer, const binbuf_t * const msg)
{
    assert(peer != NULL);

    return true;
}


bool iasp_network_receive(iasp_peer_t * const peer, binbuf_t * const msg)
{
    assert(peer != NULL);

    return true;
}


bool iasp_network_peer_init(iasp_peer_t * const peer, iasp_ip_t * const ip, const uint16_t port)
{
    int s;

    assert(peer != NULL);

    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    peer->aux = s;

    return true;
}


bool iasp_network_peer_destroy(iasp_peer_t * const peer)
{
    assert(peer != NULL);

    close((int)peer->aux);

    return true;
}
