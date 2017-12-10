#include "peer.h"
#include "types.h"
#include "crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


/* peer data storage type */
typedef struct _iasp_peer_data_t {
    iasp_identity_t id;
    const iasp_pkey_t *pkey;

    bool priv;
    bool blacklist;

    struct _iasp_peer_data_t *next;
} iasp_peer_data_t;

/* list head */
iasp_peer_data_t *head = NULL;
iasp_peer_data_t *tail = NULL;


/* private methods */
static iasp_peer_data_t * iasp_peer_data_new(void);
static iasp_peer_data_t * iasp_peer_by_id(const iasp_identity_t * const id);


static iasp_peer_data_t * iasp_peer_data_new()
{
    iasp_peer_data_t *new_peer_data;

    /* allocate structure */
    new_peer_data = malloc(sizeof(iasp_peer_data_t));
    if(new_peer_data == NULL) {
        goto alloc_failed;
    }

    /* zeroize */
    memset(new_peer_data, 0, sizeof(iasp_peer_data_t));

alloc_failed:
    return new_peer_data;
}


static iasp_peer_data_t * iasp_peer_by_id(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd = head;

    while(pd != NULL) {
        if(memcmp(id, &pd->id, sizeof(iasp_identity_t)) == 0) {
            break;
        }
        pd = pd->next;
    }

    return pd;
}


bool iasp_peer_add(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd;

    if(iasp_peer_by_id(id) != NULL) {
        /* peer exists */
        return false;
    }

    /* allocate structure */
    pd = iasp_peer_data_new();
    if(pd == NULL) {
        /* alloc failed */
        return false;
    }

    /* copy id data */
    memcpy(&pd->id, id, sizeof(iasp_identity_t));

    /* add to list */
    if(head == NULL) {
        head = tail = pd;
    }
    else {
        tail->next = pd;
        tail = pd;
    }

    return true;
}


bool iasp_peer_add_pkey(const iasp_pkey_t * const pkey)
{
    iasp_peer_data_t *pd;
    iasp_identity_t peer_id;

    /* calculate id for provided pkey */
    crypto_get_pkey_id(pkey, &peer_id);

    /* get peer data, create if not found */
    pd = iasp_peer_by_id(&peer_id);
    if(pd == NULL) {
        iasp_peer_add(&peer_id);
        pd = tail;
    }

    /* set pkey */
    if(pd->pkey != NULL) {
        return false;
    }
    pd->pkey = pkey;

    return true;
}


void iasp_peer_blacklist(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd;

    pd = iasp_peer_by_id(id);
    if(pd == NULL) {
        return;
    }

    pd->blacklist = true;
}


void iasp_peer_privilege(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd;

    pd = iasp_peer_by_id(id);
    if(pd == NULL) {
        return;
    }

    pd->priv = true;
}


bool iasp_peer_is_privileged(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd;

    pd = iasp_peer_by_id(id);

    return pd == NULL ? false : pd->priv;
}


bool iasp_peer_is_trusted(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd;

    pd = iasp_peer_by_id(id);

    return pd == NULL ? false : !pd->blacklist;
}


const iasp_pkey_t * iasp_peer_get_pkey(const iasp_identity_t * const id)
{
    iasp_peer_data_t *pd;

    pd = iasp_peer_by_id(id);
    if(pd == NULL) {
        return NULL;
    }

    return pd->pkey;
}
