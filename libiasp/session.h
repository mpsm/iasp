#ifndef __IASP_SESSION_H__
#define __IASP_SESSION_H__

#include "network.h"
#include "proto.h"
#include "types.h"
#include "role.h"

#include <stdint.h>
#include <stdbool.h>


typedef struct {
    iasp_identity_t id;
    iasp_nonce_t nonce;
    iasp_key_t key;
    iasp_spi_t spi;
    iasp_session_flags_t flags;
} iasp_session_side_data_t;


typedef enum {
    SESSION_SIDE_INITIATOR,
    SESSION_SIDE_RESPONDER,

    /* counter */
    SESSION_SIDE_COUNT,
} iasp_session_side_t;


typedef enum {
    SESSION_CMD_OK = 0,
    SESSION_CMD_ERROR = 1,
    SESSION_CMD_TIMEOUT = 2,
    SESSION_CMD_INVALID_MSG = 3,
    SESSION_CMD_NOMEM = 4,

    SESSION_CMD_MAX
} iasp_session_result_t;


typedef struct {
    bool active;
    iasp_proto_ctx_t pctx;
    iasp_salt_t salt;
    iasp_spn_code_t spn;
    iasp_session_side_t side;
    iasp_sigtype_t peer_auth_meth;

    /* negotiation sides data */
    iasp_session_side_data_t sides[SESSION_SIDE_COUNT];

    /* auxiliary data, mode specific */
    void *aux;
} iasp_session_t;


/* global methods */
void iasp_sessions_reset(void);
void iasp_session_set_role(iasp_role_t r);
iasp_session_t *iasp_session_new(const iasp_address_t *addr, const iasp_address_t *peer);

/* per-session methods */
void iasp_session_init(iasp_session_t * const this, const iasp_address_t *addr, const iasp_address_t *peer_addr);
void iasp_session_respond(iasp_session_t * const this);
iasp_session_result_t iasp_session_handle_addr(iasp_address_t * const addr);
iasp_session_result_t iasp_session_handle_any(void);

/* commands */
iasp_session_result_t iasp_session_start(const iasp_address_t *addr, const iasp_address_t *peer);

#endif
