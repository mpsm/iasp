#include "network.h"
#include "types.h"
#include "binbuf.h"

#include <sys/time.h>
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


/* private data */
static struct posix_net_aux read_aux;


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


/* INFO: thread unsafe */
bool iasp_network_receive(const iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg,
        unsigned int timeout)
{
    struct posix_net_aux *my_aux;
    ssize_t rcvd;
    socklen_t saslen = sizeof(struct sockaddr_in6);
    fd_set rfds;
    struct timeval tv;
    int retval;

    assert(address != NULL);
    assert(peer != NULL);

    assert(address->aux != NULL);
    assert(peer->aux == NULL);


    /* init aux data */
    my_aux = AUX(address);
    memset(&read_aux, 0, sizeof(struct posix_net_aux));

    /* set timeout */
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    /* set fd mask */
    FD_ZERO(&rfds);
    FD_SET(my_aux->s, &rfds);

    /* wait for message */
    retval = select(my_aux->s + 1, &rfds, NULL, NULL, &tv);
    if(retval == -1) {
        return false;
    }

    /* check if timeout */
    if(retval == 0) {
        /* timeout */
    }

    /* ensure there is a data on socket */
    if(!FD_ISSET(my_aux->s, &rfds)) {
        return false;
    }

    /* read message */
    rcvd = recvfrom(my_aux->s, msg->buf, msg->size, 0, (struct sockaddr *)&read_aux, &saslen);
    if(rcvd == -1) {
        return false;
    }
    msg->size = (size_t)rcvd;
    peer->aux = &read_aux;

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

    /* get aux data */
    aux = AUX(address);
    if(aux == NULL) {
        return false;
    }

    /* close socket */
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

    iasp_network_address_init_empty(address);
    aux = AUX(address);

    /* init sin structure */
    aux->sin.sin6_family = AF_INET6;
    aux->sin.sin6_port = htons(port);
    aux->sin.sin6_scope_id = 1; /* TODO: find actual scope */
    aux->sin.sin6_flowinfo = 0;
    assert(sizeof(iasp_ip_t) == sizeof(struct in6_addr));
    memcpy(&aux->sin.sin6_addr, ip, sizeof(struct in6_addr));
}


void iasp_network_address_init_empty(iasp_address_t * const address)
{
    struct posix_net_aux *aux;

    assert(address != NULL);

    /* init aux structure */
    aux = malloc(sizeof(struct posix_net_aux));
    memset(aux, 0, sizeof(struct posix_net_aux));
    address->aux = aux;
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


bool iasp_network_address_init_str(iasp_address_t * const address, const char *ip, const uint16_t port)
{
    iasp_ip_t localip;

    if(!iasp_network_ip_from_str(&localip, ip)) {
        return false;
    }

    iasp_network_address_init(address, &localip, port);
    return true;
}


/* INFO: thread unsafe */
#define IP_STR_BUFSIZE (4*8 + (8 - 1))
const char *iasp_network_ip_to_str(const iasp_ip_t * const ip)
{
    static char buf[IP_STR_BUFSIZE];

    memset(buf, 0, IP_STR_BUFSIZE);

    return inet_ntop(AF_INET6, (struct in6_addr *)ip, buf, IP_STR_BUFSIZE);
}


bool iasp_network_address_equal(const iasp_address_t * const left, const iasp_address_t * const right)
{
    assert(left != NULL);
    assert(right != NULL);

    return (memcmp(iasp_network_address_ip(left), iasp_network_address_ip(right), sizeof(iasp_ip_t)) == 0)
            && iasp_network_address_port(left) == iasp_network_address_port(right);
}


bool iasp_network_receive_any(iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg,
        unsigned int timeout)
{

    return false;
}


void iasp_network_address_dup(const iasp_address_t * const address, iasp_address_t *new)
{
    struct posix_net_aux *aux, *new_aux;

    assert(address != NULL);
    assert(new != NULL);

    aux = AUX(address);
    new_aux = malloc(sizeof(struct posix_net_aux));
    memcpy(new_aux, aux, sizeof(struct posix_net_aux));
    new->aux = new_aux;
}
