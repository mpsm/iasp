#ifndef __IASP_SESSION_H__
#define __IASP_SESSION_H__

#include "address.h"
#include "binbuf.h"
#include "config.h"
#include "crypto.h"
#include "decode.h"
#include "encode.h"
#include "ffd.h"
#include "field.h"
#include "message.h"
#include "network.h"
#include "proto.h"
#include "security.h"
#include "spn.h"
#include "streambuf.h"
#include "tp.h"
#include "trust.h"
#include "types.h"


#include <stdint.h>
#include <stdbool.h>

#define IASP_DEFAULT_PORT           (35491)

/* command status */
typedef enum {
    IASP_CMD_OK = 0,
    IASP_CMD_ERROR = 1,
    IASP_CMD_TIMEOUT = 2,
    IASP_CMD_INVALID_MSG = 3,
    IASP_CMD_NOMEM = 4,

    IASP_CMD_MAX
} iasp_result_t;


/* event definition */
typedef enum {
    IASP_EVENT_ESTABLISHED,
    IASP_EVENT_TERMINATED,
    IASP_EVENT_REDIRECT,

    /* sentinel */
    IASP_EVENT_MAX
} iasp_event_t;


/* negotiation side data */
typedef struct {
    iasp_identity_t id;
    iasp_nonce_t nonce;
    iasp_key_t key;
    iasp_spi_t spi;
    iasp_session_flags_t flags;
} iasp_side_data_t;


/* session data */
typedef struct _iasp_session_t {
    bool active;
    iasp_proto_ctx_t pctx;
    iasp_salt_t salt;
    iasp_spn_code_t spn;
    iasp_session_side_t side;
    bool established;

    /* negotiation sides data */
    iasp_side_data_t sides[SESSION_SIDE_COUNT];

    /* redirected session pointer */
    struct _iasp_session_t *redirect;

    /* token */
    iasp_token_t token;

    /* auxiliary data, mode specific */
    void *aux;
} iasp_session_t;


/* event handler type */
typedef void (*iasp_session_cb_t)(iasp_session_t * const s, iasp_event_t e);
typedef void (*iasp_session_userdata_cb_t)(iasp_session_t * const s, binbuf_t * const sb);


/* init IASP */
void iasp_init(iasp_role_t role, uint8_t *buf, size_t bufsize);

/* setters */
void iasp_set_hint(const char *s);
void iasp_set_tpaddr(const iasp_address_t *const tpaddr);

/* get my role */
iasp_role_t iasp_get_role(void);

/* set callbacks */
void iasp_session_set_cb(iasp_session_cb_t cb);
void iasp_session_set_userdata_cb(iasp_session_userdata_cb_t cb);

/* session commands */
iasp_session_t * iasp_session_start(const iasp_address_t *addr, const iasp_address_t *peer);
iasp_result_t iasp_session_handle_addr(iasp_address_t * const addr);
iasp_result_t iasp_session_handle_any(void);
bool iasp_session_send_userdata(iasp_session_t *s, const uint8_t *data, const size_t datasize);
bool iasp_session_terminate(iasp_session_t * const s);
void iasp_session_destroy(void);


#endif
