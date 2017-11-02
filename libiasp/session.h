#ifndef __IASP_SESSION_H__
#define __IASP_SESSION_H__

#include "network.h"
#include "proto.h"
#include "types.h"

#include <stdint.h>
#include <stdbool.h>


typedef struct {
    bool active;
    iasp_proto_ctx_t pctx;

    /* spn code */
    iasp_spn_code_t spn;

    /* IDs */
    iasp_identity_t iid;
    iasp_identity_t rid;

    /* NONCEs */
    iasp_nonce_t rnonce;
    iasp_nonce_t inonce;

} iasp_session_t;


/* global methods */
void iasp_sessions_reset(void);
void iasp_session_set_role(iasp_role_t r);
iasp_session_t *iasp_session_new(const iasp_address_t *addr, const iasp_address_t *peer);

/* per-session methods */
void iasp_session_init(iasp_session_t * const this, const iasp_address_t *addr, const iasp_address_t *peer_addr);
void iasp_session_start(const iasp_address_t *addr, const iasp_address_t *peer);
void iasp_session_respond(iasp_session_t * const this);
void iasp_session_handle_addr(const iasp_address_t * const addr);


#endif
