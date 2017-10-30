#include "network.h"
#include "types.h"
#include "binbuf.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


/* auxiliary network structure */
struct posix_net_aux {
    int s;
    struct sockaddr_in6 sin;
};


#define AUX(x) ((struct posix_net_aux *)x->aux)


bool iasp_network_send(const iasp_address_t * const address, const iasp_address_t * const peer, const binbuf_t * const msg)
{
    struct posix_net_aux *my_aux, *peer_aux;

    assert(address != NULL);
    assert(peer != NULL);

    my_aux = AUX(address);
    peer_aux = AUX(peer);

    return sendto(my_aux->s, msg->buf, msg->size, 0, (struct sockaddr *)&peer_aux->sin, sizeof(struct sockaddr_in6)) != -1;
}


bool iasp_network_receive(const iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg)
{
    struct posix_net_aux *my_aux, *peer_aux;
    struct sockaddr_storage sas;
    ssize_t rcvd;
    socklen_t saslen = sizeof(sas);

    assert(address != NULL);
    assert(peer != NULL);

    my_aux = AUX(address);
    peer_aux = AUX(peer);

    /* read message */
    rcvd = recvfrom(my_aux->s, msg->buf, msg->size, 0, (struct sockaddr *)&sas, &saslen);
    if(rcvd == -1) {
        return false;
    }
    msg->size = (size_t)rcvd;

    /* process peer address */
    memset(peer_aux, 0, sizeof(*peer_aux));

    return true;
}


bool iasp_network_add_address(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port)
{
    struct posix_net_aux *aux;

    /* init address */
    iasp_network_address_init(address, ip, port);
    aux = AUX(address);

    /* create socket */
    if((aux->s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        return false;
    }

    /* bind socket */
    if(bind(aux->s, (struct sockaddr *)&aux->sin, sizeof(aux->sin)) == -1) {
        close(aux->s);
        iasp_network_address_destroy(address);
        return false;
    }

    return true;
}


bool iasp_network_release_address(iasp_address_t * const address)
{
    struct posix_net_aux *aux;

    assert(address != NULL);

    /* close socket */
    aux = AUX(address);
    if(close(aux->s) == -1) {
        return false;
    }

    /* destroy address structure */
    iasp_network_address_destroy(address);

    return true;
}


void iasp_network_address_init(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port)
{
    struct posix_net_aux *aux;

    assert(address != NULL);

    /* init aux structure */
    aux = malloc(sizeof(struct posix_net_aux));
    memset(aux, 0, sizeof(struct posix_net_aux));
    address->aux = aux;

    /* init sin structure */
    aux->sin.sin6_family = AF_INET6;
    aux->sin.sin6_port = htons(port);
    aux->sin.sin6_scope_id = 1; /* TODO: find actual scope */
    aux->sin.sin6_flowinfo = 0;
    assert(sizeof(iasp_ip_t) == sizeof(struct in6_addr));
    memcpy(&aux->sin.sin6_addr, ip, sizeof(struct in6_addr));
}


void iasp_network_address_destroy(iasp_address_t * const peer)
{
    assert(peer != NULL);

    free(peer->aux);
    peer->aux = NULL;
}


void iasp_network_address2ip(const iasp_address_t * const address, iasp_ip_t * const ip)
{
    struct posix_net_aux *aux;

    assert(address != NULL);
    assert(ip != NULL);

    aux = AUX(address);
    memcpy(ip->ipdata, aux->sin.sin6_addr.__in6_u.__u6_addr8, sizeof(iasp_ip_t));
}


bool iasp_network_ip_from_str(iasp_ip_t * const ip, const char *str)
{
    assert(ip != NULL);
    assert(str != NULL);

    return inet_pton(AF_INET6, str, ip->ipdata) != -1;
}


const iasp_ip_t *iasp_network_address_ip(const iasp_address_t * const address)
{
    struct posix_net_aux *aux;

    assert(address != NULL);

    aux = AUX(address);

    return (const iasp_ip_t *)&aux->sin.sin6_addr.__in6_u.__u6_addr8;
}


uint16_t iasp_network_address_port(const iasp_address_t * const address)
{
    struct posix_net_aux *aux;

    assert(address != NULL);

    aux = AUX(address);

    return (uint16_t)aux->sin.sin6_port;
}


bool iasp_network_add_address_str(iasp_address_t * const address, const char *ip, const uint16_t port)
{
    iasp_ip_t localip;

    if(!iasp_network_ip_from_str(&localip, ip)) {
        return false;
    }

    return iasp_network_add_address(address, &localip, port);
}
