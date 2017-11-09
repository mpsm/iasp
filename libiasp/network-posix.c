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


/* address - socket map */
#define NETWORK_MAX_ADDRESS_COUNT (4)
struct {
    int s;
    const iasp_address_t *address;
} address_map[NETWORK_MAX_ADDRESS_COUNT];
unsigned int address_count = 0;


/* auxiliary network structure */
struct posix_net_aux {
    int s;
    struct sockaddr_in6 sin;
};


/* private methods */
static bool network_rebuild_set(fd_set *set, int * const max_fd);


/* private data */
static struct posix_net_aux read_peer_aux;
fd_set s;


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
bool iasp_network_receive(iasp_address_t * const address, iasp_address_t * const peer, binbuf_t * const msg,
        unsigned int timeout)
{
    struct posix_net_aux *my_aux;
    ssize_t rcvd;
    socklen_t saslen = sizeof(struct sockaddr_in6);
    fd_set rfds;
    struct timeval tv;
    bool read_any = false;
    int max_fd;
    int recv_fd;

    assert(address != NULL);
    assert(peer != NULL);
    assert(peer->aux == NULL);

    /* init aux data */
    if(address->aux == NULL) {
        read_any = true;
    }
    else {
        my_aux = AUX(address);
    }

    /* cleanup reader aux data */
    memset(&read_peer_aux, 0, sizeof(struct posix_net_aux));

    /* set timeout */
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    /* setup descriptor mask */
    if(read_any) {
        network_rebuild_set(&rfds, &max_fd);
    }
    else {
        FD_ZERO(&rfds);
        FD_SET(my_aux->s, &rfds);
        max_fd = my_aux->s + 1;
    }

    /* wait for message */
    recv_fd = select(max_fd, &rfds, NULL, NULL, &tv);
    if(recv_fd == -1) {
        return false;
    }

    /* check if timeout */
    if(recv_fd == 0) {
        return false;
    }

    /* ensure there is a data on socket */
    if(read_any) {
        if(!FD_ISSET(my_aux->s, &rfds)) {
            return false;
        }
    }
    else {
        unsigned int i;

        /* find receiving address */
        for(i = 0 ; i < address_count; ++i) {
            if(FD_ISSET(address_map[i].s, &rfds)) {
                break;
            }
        }

        /* not found */
        if(i == address_count) {
            abort();
        }

        /* set my address */
        address->aux = my_aux = address_map[i].address->aux;
    }

    /* read message */
    rcvd = recvfrom(my_aux->s, msg->buf, msg->size, 0, (struct sockaddr *)&read_peer_aux.sin, &saslen);
    if(rcvd == -1) {
        return false;
    }
    msg->size = (size_t)rcvd;
    peer->aux = &read_peer_aux;

    return true;
}


bool iasp_network_add_address(iasp_address_t * const address, iasp_ip_t * const ip, const uint16_t port)
{
    struct posix_net_aux *aux;

    /* check address count */
    if(address_count == NETWORK_MAX_ADDRESS_COUNT) {
        return false;
    }

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

    /* add address to map */
    address_map[address_count].address = address;
    address_map[address_count].s = aux->s;
    address_count++;

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


static bool network_rebuild_set(fd_set *set, int * const max_fd)
{
    unsigned int i;
    int max = 0;

    assert(set != NULL);

    if(address_count == 0) {
        return false;
    }

    FD_ZERO(set);
    for(i = 0; i < address_count; ++i) {
        int s = address_map[i].s;

        if(s > max) {
            max = s;
        }

        FD_SET(s, set);
    }

    if(max_fd != NULL) {
        *max_fd = max;
    }

    return true;
}

