#include "session.h"

#include "iasp.h"
#include "crypto.h"
#include "encode.h"
#include "decode.h"
#include "streambuf.h"
#include "types.h"
#include "tp.h"
#include "ffd.h"
#include "debug.h"
#include "trust.h"
#include "role.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#define IASP_SESSION_RECV_TIMEOUT (1000)


/* session handler */
typedef bool (*iasp_session_handler_t)(iasp_session_t * const, streambuf_t * const);

/* callbacks: event handler, user data */
static iasp_session_cb_t event_cb;
static iasp_session_userdata_cb_t userdata_cb;

/* session data */
static iasp_session_t sessions[IASP_CONFIG_MAX_SESSIONS];

/* rx/tx message structure */
static iasp_msg_storage_t msg;
static iasp_role_t role;

/* private methods */
static void iasp_reset_message(void);
static iasp_session_result_t iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload);
static bool iasp_session_generate_secret(iasp_session_t *s, const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx);;
static iasp_session_t *iasp_session_by_peer(const iasp_address_t * const peer);
static iasp_session_t *iasp_session_by_peer_ip(const iasp_address_t * const peer);
static iasp_session_t *iasp_session_by_address_pair(const iasp_address_t * const myaddress, const iasp_address_t * const peer);
static bool iasp_send_status(iasp_session_t * const s, iasp_status_t status);
static bool iasp_session_send_msg(iasp_session_t * const s, streambuf_t * payload, iasp_msg_type_t mt, bool answer, bool encrypted);
static bool iasp_session_send_mgmt(iasp_session_t * const s, streambuf_t * payload, bool answer);
static bool iasp_session_send_hmsg(iasp_session_t * const s, streambuf_t * payload, bool answer);
static void iasp_session_get_iv(iasp_session_t *s, binbuf_t *bbiv, bool output);
static void iasp_session_get_aad(iasp_session_t * const s, binbuf_t *bbaad);
static bool iasp_session_decrypt_msg(iasp_session_t * const s, streambuf_t * const payload);


/* message handlers - handshake */
static bool iasp_handler_init_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_hello(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_init_auth(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_resp_auth(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_redirect(iasp_session_t * const, streambuf_t * const);

/* message handlers - management */
static bool iasp_handler_mgmt_req(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_mgmt_install(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_mgmt_spi(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_mgmt_token(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_mgmt_status(iasp_session_t * const, streambuf_t * const);
static bool iasp_handler_mgmt_terminate(iasp_session_t * const, streambuf_t * const);


/* lookup table */
#define MSG_CODE(X, Y) (((uint16_t)X << 8) + Y)
typedef struct {
    uint16_t msg;
    iasp_session_handler_t handler;
} session_handler_lookup_t;


/* CD handlers */
static const session_handler_lookup_t cd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_REDIRECT), iasp_handler_redirect},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_INSTALL), iasp_handler_mgmt_install},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_STATUS), iasp_handler_mgmt_status},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_TOKEN), iasp_handler_mgmt_token},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_TERMINATE), iasp_handler_mgmt_terminate},
        {0, NULL},
};

/* FFD handlers */
static const session_handler_lookup_t ffd_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_REDIRECT), iasp_handler_redirect},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_INSTALL), iasp_handler_mgmt_install},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_STATUS), iasp_handler_mgmt_status},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_TOKEN), iasp_handler_mgmt_token},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_TERMINATE), iasp_handler_mgmt_terminate},
        {0, NULL},
};

/* TP handlers */
static const session_handler_lookup_t tp_session_handlers[] =
{
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO), iasp_handler_init_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_HELLO), iasp_handler_resp_hello},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_AUTH), iasp_handler_init_auth},
        {MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_RESP_AUTH), iasp_handler_resp_auth},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_REQ), iasp_handler_mgmt_req},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_SPI), iasp_handler_mgmt_spi},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_STATUS), iasp_handler_mgmt_status},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_TOKEN), iasp_handler_mgmt_token},
        {MSG_CODE(IASP_MSG_MGMT, IASP_MGMT_TERMINATE), iasp_handler_mgmt_terminate},
        {0, NULL},
};

const session_handler_lookup_t *handlers[IASP_ROLE_MAX] =
{
        cd_session_handlers, ffd_session_handlers, tp_session_handlers
};


void iasp_session_set_cb(iasp_session_cb_t cb)
{
    assert(cb != NULL);
    event_cb = cb;
}


void iasp_session_set_userdata_cb(iasp_session_userdata_cb_t cb)
{
    assert(cb != NULL);
    userdata_cb = cb;
}


void iasp_sessions_reset()
{
    memset(sessions, 0, IASP_CONFIG_MAX_SESSIONS * sizeof(iasp_session_t));
}


void iasp_session_set_role(iasp_role_t r)
{
    assert(role < IASP_ROLE_MAX);
    role = r;
}


iasp_session_t *iasp_session_new(const iasp_address_t *addr, const iasp_address_t *peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        if(sessions[i].active == false) {
            iasp_session_t *s = &sessions[i];

            iasp_session_init(s, role, addr, peer);
            debug_log("Created new session: %p\n", s);
            return s;
        }
    }

    return NULL;
}


void iasp_session_init(iasp_session_t * const this, iasp_role_t srole, const iasp_address_t *addr, const iasp_address_t *peer_addr)
{
    assert(addr != NULL);
    assert(peer_addr != NULL);

    memset(this, 0, sizeof(iasp_session_t));

    this->active = true;
    iasp_proto_ctx_init(&this->pctx);
    iasp_network_address_dup(addr, &this->pctx.addr);
    iasp_network_address_dup(peer_addr, &this->pctx.peer);

    switch(srole) {
        case IASP_ROLE_TP:
        {
            iasp_tpdata_t *tpd = NULL;

            iasp_tpdata_init(&tpd);
            this->aux = tpd;
            break;
        }

        default:
            break;
    }
}


const iasp_session_t * iasp_session_start(const iasp_address_t *addr, const iasp_address_t *peer)
{
    streambuf_t *sb;
    iasp_session_t *s;

    assert(addr != NULL);
    assert(peer != NULL);

    /* get new session */
    s = iasp_session_new(addr, peer);
    if(s == NULL) {
        abort();
    }

    /* prepare headers */
    s->pctx.msg_type = IASP_MSG_HANDSHAKE;
    s->side = SESSION_SIDE_INITIATOR;

    /* get payload space */
    iasp_proto_reset_payload();
    sb = iasp_proto_get_payload_sb();

    /* encode hello message - set nonce and ids*/
    iasp_reset_message();
    crypto_gen_nonce(&msg.hmsg_init_hello.inonce);
    memcpy(&s->sides[SESSION_SIDE_INITIATOR].nonce, &msg.hmsg_init_hello.inonce, sizeof(iasp_nonce_t));
    crypto_get_ids(&msg.hmsg_init_hello.ids);
    if(!iasp_encode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        abort();
    }

    /* proto send message */
    if(!iasp_session_send_hmsg(s, NULL, false)) {
        /* TODO: destroy session or retry */
        return NULL;
    }

    return s;
}


iasp_session_result_t iasp_session_handle_any()
{
    iasp_address_t addr = { NULL };

    return iasp_session_handle_addr(&addr);
}


iasp_session_result_t iasp_session_handle_addr(iasp_address_t * const addr)
{
    iasp_proto_ctx_t pctx;
    streambuf_t *sb;

    assert(addr != NULL);

    /* reset context */
    iasp_proto_ctx_init(&pctx);
    iasp_reset_message();

    /* receive with timeout */
    if(!iasp_proto_receive(addr, &pctx, NULL, IASP_SESSION_RECV_TIMEOUT)) {
        return SESSION_CMD_TIMEOUT;
    }
    sb = iasp_proto_get_payload_sb();

    debug_log("Received msg: %u bytes from ", sb->size);
    debug_print_address(&pctx.peer);
    debug_newline();
    debug_log("Received on ");
    debug_print_address(&pctx.addr);
    debug_newline();

    /* handle received message */
    return iasp_handle_message(&pctx, sb);
}


static void iasp_reset_message()
{
    memset(&msg, 0, sizeof(msg));
}


/* MESSAGE HANDLERS */
static iasp_session_result_t iasp_handle_message(const iasp_proto_ctx_t * const pctx, streambuf_t * const payload)
{
    unsigned int msg_code;
    uint16_t lookup_code;
    const session_handler_lookup_t *lookup;
    iasp_session_t *s = NULL;

    /* find session */
    {
        unsigned int i;

        for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
            iasp_proto_ctx_t *p;

            /* omit inactive sessions */
            if(sessions[i].active == false) {
                continue;
            }

            p = &sessions[i].pctx;

            /* match my address */
            if(!iasp_network_address_equal(&p->addr, &pctx->addr)) {
                continue;
            }

            /* match peer address */
            if(iasp_network_address_equal(&p->peer, &pctx->peer)) {
                s = &sessions[i];
                debug_log("Found session: %p\n", s);
                break;
            }
        }
    }

    /* create new session */
    if(s == NULL) {
#if 0
        if(lookup_code != MSG_CODE(IASP_MSG_HANDSHAKE, IASP_HMSG_INIT_HELLO)) {
            return SESSION_CMD_INVALID_MSG;
        }
#endif
        s = iasp_session_new(&pctx->addr, &pctx->peer);
        if(s == NULL) {
            return SESSION_CMD_NOMEM;
        }
    }
    else {
        /* copy crucial data */
        s->pctx.input_seq = pctx->input_seq;
        s->pctx.input_spi = pctx->input_spi;

        /* decrypt if received msg is encrypted */
        if(pctx->encrypted) {
            if(pctx->msg_type != IASP_MSG_USER && pctx->msg_type != IASP_MSG_MGMT) {
                return SESSION_CMD_INVALID_MSG;
            }
            if(!iasp_session_decrypt_msg(s, payload)) {
                debug_log("Invalid decrypt.\n");
                return SESSION_CMD_INVALID_MSG;
            }
        }
    }

    /* check message type for user data */
    if(pctx->msg_type == IASP_MSG_USER) {
        if(userdata_cb) {
            userdata_cb(s, iasp_proto_get_payload_sb());
            return SESSION_CMD_OK;
        }
    }

    /* get message code */
    if(!iasp_decode_varint(payload, &msg_code)) {
        return SESSION_CMD_INVALID_MSG;
    }

    /* check range */
    if(msg_code >= UINT8_MAX) {
        return SESSION_CMD_INVALID_MSG;
    }

    /* find handler */
    lookup_code = MSG_CODE(pctx->msg_type, msg_code);
    lookup = handlers[role];
    while(lookup->msg != 0) {
        if(lookup->msg == lookup_code) {
            break;
        }
        lookup++;
    }

    /* found handler */
    if(lookup->handler == NULL) {
        return SESSION_CMD_INVALID_MSG;
    }

    /* reset decode space */
    iasp_reset_message();

    /* handle message */
    if(lookup->handler(s, payload) == false) {
        return SESSION_CMD_ERROR;
    }

    return SESSION_CMD_OK;
}


static bool iasp_handler_init_hello(iasp_session_t * const s, streambuf_t *sb)
{
    streambuf_t *reply;
    iasp_identity_t *iid = NULL;
    iasp_session_side_data_t *i, *r;
    unsigned int j;

    /* decode message */
    if(!iasp_decode_hmsg_init_hello(sb, &msg.hmsg_init_hello)) {
        debug_log("Cannot decode init hello message.\n");
        return false;
    }

    /* get side data */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* mark session side */
    s->side = SESSION_SIDE_RESPONDER;

    /* choose spn */
    s->spn = security_choose_spn(&msg.hmsg_init_hello.ids);
    if(s->spn == IASP_SPN_NONE) {
        debug_log("Unable choose SPN.\n");
        return false;
    }

    /* save initiator ID */
    for(j = 0; j < msg.hmsg_init_hello.ids.id_count; ++j) {
        if(msg.hmsg_init_hello.ids.id[j].spn == s->spn) {
            iid = &msg.hmsg_init_hello.ids.id[j];
            break;
        }
    }
    if(iid == NULL) {
        abort();
    }
    memcpy(&i->id, iid, sizeof(iasp_identity_t));

    /* save initiator nonce */
    memcpy(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t));

    /* save peer's IDs for child session negotiation */
    if(role == IASP_ROLE_TP) {
        iasp_tpdata_set_ids(s->aux, &msg.hmsg_init_hello.ids);
    }

    /* prepare for reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();
    s->pctx.answer = true;

    /* set and save own ID */
    {
        iasp_identity_t *myid = role == IASP_ROLE_CD ? &msg.hmsg_redirect.id : &msg.hmsg_resp_hello.id;
        crypto_get_id(s->spn, myid);
        memcpy(&r->id, myid, sizeof(iasp_identity_t));
    }

    /* generate and set NONCE */
    crypto_gen_nonce(&r->nonce);

    /* ================ ROLE DEPEND =================== */
    r->flags.byte = 0;
    if(role != IASP_ROLE_CD) {
        /* set session flags */
        if(!iasp_trust_is_trusted_peer(&i->id)) {
            r->flags.bits.send_hint = true;
        }

        /* set nonce */
        memcpy(&msg.hmsg_resp_hello.rnonce, &r->nonce, sizeof(iasp_nonce_t));

        /* add initiator NONCE */
        memcpy(&msg.hmsg_resp_hello.inonce, &i->nonce, sizeof(iasp_nonce_t));

        /* save flags */
        msg.hmsg_resp_hello.flags = r->flags;

        /* send responder hello */
        if(!iasp_encode_hmsg_resp_hello(reply, &msg.hmsg_resp_hello)) {
            abort();
        }
    }
    else {
        const iasp_address_t *tpaddr;

        /* add TP address and redirect */
        tpaddr = iasp_get_tpaddr();
        if(tpaddr == NULL) {
            debug_log("Cannot get TP address to redirect.\n");
            return false;
        }

        /* deep copy (risk considered) */
        memcpy(&msg.hmsg_redirect.tp_address, tpaddr, sizeof(iasp_address_t));

        /* send redirect message */
        if(!iasp_encode_hmsg_redirect(sb, &msg.hmsg_redirect)) {
            abort();
        }
    }
    /* ================ ROLE DEPEND =================== */

    /* send reply */
    return iasp_session_send_hmsg(s, reply, true);
}


static bool iasp_handler_resp_hello(iasp_session_t * const s, streambuf_t * const sb)
{
    uint8_t byte;
    streambuf_t *reply;
    iasp_session_side_data_t *i, *r;

    /* mark session side */
    s->side = SESSION_SIDE_INITIATOR;

    /* decode message */
    if(!iasp_decode_hmsg_resp_hello(sb, &msg.hmsg_resp_hello)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* check my nonce */
    if(memcmp(&i->nonce, &msg.hmsg_resp_hello, sizeof(iasp_nonce_t)) != 0) {
        debug_log("INONCE mismatch.\n");
        return false;
    }

    /* get SPN */
    s->spn = msg.hmsg_resp_hello.id.spn;

    /* get my ID */
    if(!crypto_get_id(s->spn, &i->id)) {
        return false;
    }

    /* get responder ID */
    memcpy(&r->id, &msg.hmsg_resp_hello.id, sizeof(iasp_identity_t));

    /* get responder NONCE */
    memcpy(&r->nonce, &msg.hmsg_resp_hello.rnonce, sizeof(iasp_nonce_t));

    /* get responder flags */
    r->flags = msg.hmsg_resp_hello.flags;

    /* prepare response */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* ================ ROLE DEPEND =================== */
    i->flags.byte = 0;
    if(role != IASP_ROLE_CD) {
        iasp_ffddata_t *ffd = (iasp_ffddata_t *)s->aux;

        /* set ephemeral key */
        msg.hmsg_init_auth.has_dhkey = true;
        crypto_ecdhe_genkey(s->spn, &msg.hmsg_init_auth.dhkey, &ffd->ecdhe_ctx);

        if(!iasp_trust_is_trusted_peer(&r->id)) {
            i->flags.bits.send_hint = true;
        }
    }
    else {
        if(!iasp_trust_is_trusted_tp(&r->id)) {
            i->flags.bits.oob_auth = true;
            i->flags.bits.send_pkey = true;
        }
    }
    msg.hmsg_init_auth.flags = i->flags;
    /* ================ ROLE DEPEND =================== */

    /* set hint if needed */
    if(r->flags.bits.send_hint) {
        msg.hmsg_init_auth.has_hint = true;
        if(!iasp_get_hint(&msg.hmsg_init_auth.hint)) {
            return false;
        }
    }

    /* set public key if needed */
    if(r->flags.bits.send_pkey) {
        msg.hmsg_init_auth.has_pkey = true;
        if(!crypto_get_pkey(s->spn, &msg.hmsg_init_auth.pkey)) {
            /* bad SPN - impossible to happen */
            abort();
        }
    }

    /* check if OOB key signature is needed */
    if(r->flags.bits.oob_auth) {
        msg.hmsg_init_auth.has_oobsig = true;

        /* signing */
        if(!crypto_sign_init(s->spn, IASP_SIG_HMAC)) {
            abort();
        }
        byte = (uint8_t)s->spn;
        crypto_sign_update(&byte, sizeof(byte));
        crypto_sign_update(i->id.data, sizeof(i->id.data));
        crypto_sign_update(r->id.data, sizeof(r->id.data));
        crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));

        /* add optional fields to signature */
        if(msg.hmsg_init_auth.has_dhkey) {
            crypto_sign_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
        }
        if(msg.hmsg_init_auth.has_hint) {
            crypto_sign_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
        }
        if(msg.hmsg_init_auth.has_pkey) {
            crypto_sign_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
        }

        /* finalize HMAC signature */
        msg.hmsg_init_auth.has_oobsig = true;
        if(!crypto_sign_final(&msg.hmsg_init_auth.oobsig)) {
            abort();
        }
    }

    /* set nonces */
    memcpy(&msg.hmsg_init_auth.inonce.data, i->nonce.data, sizeof(iasp_nonce_t));
    memcpy(&msg.hmsg_init_auth.rnonce.data, r->nonce.data, sizeof(iasp_nonce_t));

    /* sign everything */
    if(!crypto_sign_init(s->spn, IASP_SIG_EC)) {
        abort();
    }
    byte = (uint8_t)s->spn;
    crypto_sign_update(&byte, sizeof(byte));
    crypto_sign_update(i->id.data, sizeof(i->id.data));
    crypto_sign_update(r->id.data, sizeof(r->id.data));
    crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));

    /* add optional fields to signature */
    if(msg.hmsg_init_auth.has_dhkey) {
        crypto_sign_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
    }
    if(msg.hmsg_init_auth.has_hint) {
        crypto_sign_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
    }
    if(msg.hmsg_init_auth.has_pkey) {
        crypto_sign_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
    }
    if(msg.hmsg_init_auth.has_oobsig) {
        crypto_sign_update(msg.hmsg_init_auth.oobsig.sigdata, msg.hmsg_init_auth.oobsig.siglen);
    }

    /* finalize signature */
    if(!crypto_sign_final(&msg.hmsg_init_auth.sig)) {
        abort();
    }

    /* encode reply */
    if(!iasp_encode_hmsg_init_auth(reply, &msg.hmsg_init_auth)) {
       abort();
    }

    /* send response */
    return iasp_session_send_hmsg(s, reply, false);
}


static bool iasp_handler_init_auth(iasp_session_t * const s, streambuf_t * const sb)
{
    uint8_t byte;
    streambuf_t *reply;
    iasp_tpdata_t *tpd = (iasp_tpdata_t *)s->aux;
    const iasp_pkey_t *pkey;
    iasp_session_side_data_t *i, *r;

    /* decode message */
    if(!iasp_decode_hmsg_init_auth(sb, &msg.hmsg_init_auth)) {
        debug_log("Cannot decode init auth message.\n");
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* check nonces */
    if(memcmp(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("INONCE mismatch.\n");
        return false;
    }
    if(memcmp(&r->nonce, &msg.hmsg_init_auth.rnonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("RNONCE mismatch.\n");
        return false;
    }

    /* set initiator flags */
    i->flags = msg.hmsg_init_auth.flags;

    /* set SPIs */
    memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
    memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));

    /* check hint if asked for */
    if(r->flags.bits.send_hint) {
        if(!msg.hmsg_init_auth.has_hint) {
            debug_log("HINT is missed.\n");
            return false;
        }

        debug_log("Hint: %.*s.\n", msg.hmsg_init_auth.hint.hintlen, (const char *)msg.hmsg_init_auth.hint.hintdata);
        if(!security_use_hint(&msg.hmsg_init_auth.hint)) {
            debug_log("Error during hint processing!\n");
            return false;
        }
    }

    /* check pkey if asked for */
    if(r->flags.bits.send_pkey) {
        if(!msg.hmsg_init_auth.has_pkey) {
            debug_log("PKEY is missed.\n");
            return false;
        }

        debug_log("PKEY received.\n");
        security_add_pkey_dup(&msg.hmsg_init_auth.pkey, false);
    }

    /* it should be possible to check peer's public key by now */
    {
        const iasp_pkey_t *peer_pkey = security_get_pkey_by_id(&i->id);

        /* get peer's public key */
        if(peer_pkey == NULL) {
            debug_log("Cannot get peer's public key!\n");
            return false;
        }

        /* check if peer is authorized */
        if(!security_authorize_peer(peer_pkey)) {
            debug_log("Peer's not authorized!\n");
            return false;
        }
    }

    /* check OOB key signature if asked for */
    if(r->flags.bits.oob_auth) {
        if(!msg.hmsg_init_auth.has_oobsig) {
            debug_log("OOB key signature is missed.\n");
            return false;
        }

        /* sanity check */
        if(msg.hmsg_init_auth.oobsig.sigtype != IASP_SIG_HMAC) {
            debug_log("Invalid OOB signature.\n");
            return false;
        }

        /* check OOB signature */
        if(!crypto_verify_init(&i->id, IASP_SIG_HMAC)) {
            return false;
        }
        byte = (uint8_t)s->spn;
        crypto_verify_update(&byte, sizeof(byte));
        crypto_verify_update(i->id.data, sizeof(i->id.data));
        crypto_verify_update(r->id.data, sizeof(r->id.data));
        crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));

        /* check optional fields */
        if(msg.hmsg_init_auth.has_dhkey) {
            crypto_verify_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
        }
        if(msg.hmsg_init_auth.has_hint) {
            crypto_verify_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
        }
        if(msg.hmsg_init_auth.has_pkey) {
            crypto_verify_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
        }

        /* finalize verification */
        if(!crypto_verify_final(&msg.hmsg_init_auth.oobsig)) {
            debug_log("Peer's HMAC signature does not match!\n");
            return false;
        }

        debug_log("Peer's HMAC signature match!\n");
    }

    /* prepare data for signature verification */
    if(!crypto_verify_init(&i->id, IASP_SIG_EC)) {
        return false;
    }
    byte = (uint8_t)s->spn;
    crypto_verify_update(&byte, sizeof(byte));
    crypto_verify_update(i->id.data, sizeof(i->id.data));
    crypto_verify_update(r->id.data, sizeof(r->id.data));
    crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));

    /* choose key for ECDHE */
    if(!msg.hmsg_init_auth.has_dhkey) {
        /* find pkey by peer key id */
        pkey = security_get_pkey_by_id(&i->id);
        if(pkey == NULL) {
            return false;
        }
        debug_log("Using peer's public key for ECDHE\n");
    }
    else {
        pkey = &msg.hmsg_init_auth.dhkey;
        debug_log("Using received ephemeral key for ECDHE\n");
        crypto_verify_update(msg.hmsg_init_auth.dhkey.pkeydata, msg.hmsg_init_auth.dhkey.pkeylen);
    }

    /* verify optional fields */
    if(msg.hmsg_init_auth.has_hint && r->flags.bits.send_hint) {
        crypto_verify_update(msg.hmsg_init_auth.hint.hintdata, msg.hmsg_init_auth.hint.hintlen);
    }
    if(msg.hmsg_init_auth.has_pkey && r->flags.bits.send_pkey) {
        crypto_verify_update(msg.hmsg_init_auth.pkey.pkeydata, msg.hmsg_init_auth.pkey.pkeylen);
    }
    if(msg.hmsg_init_auth.has_oobsig && r->flags.bits.oob_auth) {
        crypto_verify_update(msg.hmsg_init_auth.oobsig.sigdata, msg.hmsg_init_auth.oobsig.siglen);
    }

    /* verify signature */
    if(!crypto_verify_final(&msg.hmsg_init_auth.sig)) {
        debug_log("Peer's signature does not match!\n");
        return false;
    }
    debug_log("Peer's signature match!\n");

    /* generate ephemeral key */
    crypto_ecdhe_genkey(s->spn, NULL, &tpd->ffd.ecdhe_ctx);

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, pkey, &tpd->ffd.ecdhe_ctx)) {
        return false;
    }

    /* prepare reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    /* set nonces */
    memcpy(&msg.hmsg_resp_auth.inonce.data, i->nonce.data, sizeof(iasp_nonce_t));
    memcpy(&msg.hmsg_resp_auth.rnonce.data, r->nonce.data, sizeof(iasp_nonce_t));

    /* extract public part of ephemeral key */
    if(!crypto_ecdhe_pkey(&tpd->ffd.ecdhe_ctx, &msg.hmsg_resp_auth.dhkey)) {
        abort();
    }

    /* set hint if needed */
    if(i->flags.bits.send_hint) {
        msg.hmsg_resp_auth.has_hint = true;
        if(!iasp_get_hint(&msg.hmsg_resp_auth.hint)) {
            return false;
        }
    }

    /* set public key if needed */
    if(i->flags.bits.send_pkey) {
        msg.hmsg_resp_auth.has_pkey = true;
        if(!crypto_get_pkey(s->spn, &msg.hmsg_resp_auth.pkey)) {
            /* bad SPN - impossible to happen */
            abort();
        }
    }

    /* check if OOB key signature is needed */
    if(i->flags.bits.oob_auth) {
        msg.hmsg_resp_auth.has_oobsig = true;

        /* signing */
        if(!crypto_sign_init(s->spn, IASP_SIG_HMAC)) {
            abort();
        }
        byte = (uint8_t)s->spn;
        crypto_sign_update(&byte, sizeof(byte));
        crypto_sign_update(i->id.data, sizeof(i->id.data));
        crypto_sign_update(r->id.data, sizeof(r->id.data));
        crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));
        crypto_sign_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

        /* add optional fields to signature */
        if(msg.hmsg_resp_auth.has_hint) {
            crypto_sign_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
        }
        if(msg.hmsg_resp_auth.has_pkey) {
            crypto_sign_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
        }

        /* finalize HMAC signature */
        msg.hmsg_resp_auth.has_oobsig = true;
        if(!crypto_sign_final(&msg.hmsg_resp_auth.oobsig)) {
            abort();
        }
    }

    /* sign negotiation */
    if(!crypto_sign_init(s->spn, IASP_SIG_EC)) {
        abort();
    }
    byte = (uint8_t)s->spn;
    crypto_sign_update(&byte, sizeof(byte));
    crypto_sign_update(i->id.data, sizeof(i->id.data));
    crypto_sign_update(r->id.data, sizeof(r->id.data));
    crypto_sign_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_sign_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_sign_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_sign_update(&r->flags.byte, sizeof(r->flags.byte));
    crypto_sign_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

    /* add optional fields to signature */
    if(msg.hmsg_resp_auth.has_hint) {
        crypto_sign_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
    }
    if(msg.hmsg_resp_auth.has_pkey) {
        crypto_sign_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
    }
    if(msg.hmsg_resp_auth.has_oobsig) {
        crypto_sign_update(msg.hmsg_resp_auth.oobsig.sigdata, msg.hmsg_resp_auth.oobsig.siglen);
    }

    /* finalize signature */
    if(!crypto_sign_final(&msg.hmsg_resp_auth.sig)) {
        abort();
    }

    /* encode reply */
    if(!iasp_encode_hmsg_resp_auth(reply, &msg.hmsg_resp_auth)) {
        return false;
    }

    /* send reply */
    if(!iasp_session_send_hmsg(s, reply, true)) {
        return false;
    }

    /* mark as established */
    s->established = true;

    /* event callback */
    if(event_cb != NULL) {
        event_cb(s, SESSION_EVENT_ESTABLISHED);
    }

    return true;
}


static bool iasp_handler_resp_auth(iasp_session_t * const s, streambuf_t * const sb)
{
    uint8_t byte;
    iasp_session_side_data_t *i, *r;
    crypto_ecdhe_context_t *ecdhe_ctx = NULL;

    /* decode message */
    if(!iasp_decode_hmsg_resp_auth(sb, &msg.hmsg_resp_auth)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* check nonces */
    if(memcmp(&i->nonce, &msg.hmsg_init_auth.inonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("INONCE mismatch.\n");
        return false;
    }
    if(memcmp(&r->nonce, &msg.hmsg_init_auth.rnonce, sizeof(iasp_nonce_t)) != 0) {
        debug_log("RNONCE mismatch.\n");
        return false;
    }

    /* check hint if asked for */
    if(i->flags.bits.send_hint) {
        if(!msg.hmsg_resp_auth.has_hint) {
            debug_log("HINT is missed.\n");
            return false;
        }

        /* use hint to get peer's certificate */
        debug_log("Hint: %.*s.\n", msg.hmsg_resp_auth.hint.hintlen, (const char *)msg.hmsg_resp_auth.hint.hintdata);
        if(!security_use_hint(&msg.hmsg_resp_auth.hint)) {
            debug_log("Error during hint processing!\n");
            return false;
        }
    }

    /* check pkey if asked for */
    if(i->flags.bits.send_pkey) {
        if(!msg.hmsg_resp_auth.has_pkey) {
            debug_log("PKEY is missed.\n");
            return false;
        }

        debug_log("PKEY received.\n");
        security_add_pkey_dup(&msg.hmsg_resp_auth.pkey, false);
    }

    /* it should be possible to check peer's public key by now */
    {
        const iasp_pkey_t *peer_pkey = security_get_pkey_by_id(&r->id);

        /* get peer's public key */
        if(peer_pkey == NULL) {
            debug_log("Cannot get peer's public key!\n");
            return false;
        }

        /* check if peer is authorized */
        if(!security_authorize_peer(peer_pkey)) {
            debug_log("Peer's not authorized!\n");
            return false;
        }
    }

    /* check OOB key signature if asked for */
    if(i->flags.bits.oob_auth) {
        if(!msg.hmsg_resp_auth.has_oobsig) {
            debug_log("OOB key signature is missed.\n");
            return false;
        }

        /* sanity check */
        if(msg.hmsg_resp_auth.oobsig.sigtype != IASP_SIG_HMAC) {
            debug_log("Invalid OOB signature.\n");
            return false;
        }

        /* check OOB signature */
        if(!crypto_verify_init(&i->id, IASP_SIG_HMAC)) {
            return false;
        }
        byte = (uint8_t)s->spn;
        crypto_verify_update(&byte, sizeof(byte));
        crypto_verify_update(i->id.data, sizeof(i->id.data));
        crypto_verify_update(r->id.data, sizeof(r->id.data));
        crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
        crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
        crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
        crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));
        crypto_verify_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

        /* check optional fields */
        if(msg.hmsg_resp_auth.has_hint) {
            crypto_verify_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
        }
        if(msg.hmsg_resp_auth.has_pkey) {
            crypto_verify_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
        }

        /* finalize verification */
        if(!crypto_verify_final(&msg.hmsg_resp_auth.oobsig)) {
            debug_log("Peer's HMAC signature does not match!\n");
            return false;
        }

        debug_log("Peer's HMAC signature match!\n");
    }

    /* verify signature */
    if(!crypto_verify_init(&r->id, IASP_SIG_EC)) {
        return false;
    }
    byte = (uint8_t)s->spn;
    crypto_verify_update(&byte, sizeof(byte));
    crypto_verify_update(i->id.data, sizeof(i->id.data));
    crypto_verify_update(r->id.data, sizeof(r->id.data));
    crypto_verify_update(i->nonce.data, sizeof(i->nonce.data));
    crypto_verify_update(r->nonce.data, sizeof(r->nonce.data));
    crypto_verify_update(&i->flags.byte, sizeof(i->flags.byte));
    crypto_verify_update(&r->flags.byte, sizeof(r->flags.byte));
    crypto_verify_update(msg.hmsg_resp_auth.dhkey.pkeydata, msg.hmsg_resp_auth.dhkey.pkeylen);

    /* add optional fields to signature */
    if(msg.hmsg_resp_auth.has_hint) {
        crypto_verify_update(msg.hmsg_resp_auth.hint.hintdata, msg.hmsg_resp_auth.hint.hintlen);
    }
    if(msg.hmsg_resp_auth.has_pkey) {
        crypto_verify_update(msg.hmsg_resp_auth.pkey.pkeydata, msg.hmsg_resp_auth.pkey.pkeylen);
    }
    if(msg.hmsg_resp_auth.has_oobsig) {
        crypto_verify_update(msg.hmsg_resp_auth.oobsig.sigdata, msg.hmsg_resp_auth.oobsig.siglen);
    }

    /* finalize verification */
    if(!crypto_verify_final(&msg.hmsg_resp_auth.sig)) {
        debug_log("Peer's signature does not match!\n");
        return false;
    }
    debug_log("Peer's signature match!\n");

    /* set SPis */
    memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
    memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));

    /* get ephemeral key if possible */
    if(role != IASP_ROLE_CD) {
        iasp_tpdata_t *tpd = s->aux;
        ecdhe_ctx = &tpd->ffd.ecdhe_ctx;
    }

    /* generate shared secret */
    if(!iasp_session_generate_secret(s, &msg.hmsg_resp_auth.dhkey, ecdhe_ctx)) {
        return false;
    }

    /* mark as established */
    s->established = true;

    /* event callback */
    if(event_cb != NULL) {
        event_cb(s, SESSION_EVENT_ESTABLISHED);
    }

    return true;
}


static bool iasp_session_generate_secret(iasp_session_t *s, const iasp_pkey_t * const pkey, const crypto_ecdhe_context_t *ecdhe_ctx)
{
    static uint8_t buffer[IASP_MAX_KEY_SIZE*2 + sizeof(iasp_salt_t)];
    static uint8_t saltbuffer[sizeof(iasp_spi_t) * 2];
    binbuf_t saltbb;
    size_t keysize = spn_get_key_size(pkey->spn);
    size_t gensize = 2*keysize + sizeof(iasp_salt_t);
    iasp_session_side_data_t *i, *r;

    assert(gensize <= sizeof(buffer));

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* prepare salt buffer */
    memcpy(saltbuffer, i->spi.spidata, sizeof(iasp_spi_t));
    memcpy(saltbuffer + sizeof(iasp_spi_t), r->spi.spidata, sizeof(iasp_spi_t));
    saltbb.buf = saltbuffer;
    saltbb.size = sizeof(saltbuffer);

    /* complete ECDHE */
    if(!crypto_ecdhe_compute_secret(pkey, ecdhe_ctx, buffer, gensize, &saltbb)) {
        return false;
    }
    debug_log("Shared secret computed: ");
    debug_print_binary(buffer, gensize);
    debug_newline();

    /* distribute material */
    memcpy(i->key.keydata, buffer, keysize);
    memcpy(r->key.keydata, buffer + keysize, keysize);
    memcpy(s->salt.saltdata, buffer + 2*keysize, sizeof(iasp_salt_t));

    /* key information */
    i->key.keysize = r->key.keysize = keysize;
    i->key.spn = r->key.spn = pkey->spn;

    return true;
}


static bool iasp_handler_redirect(iasp_session_t * const s, streambuf_t * const sb)
{
    iasp_session_side_data_t *i, *r;
    iasp_session_t *redirect;

    /* decode message */
    if(!iasp_decode_hmsg_redirect(sb, &msg.hmsg_redirect)) {
        return false;
    }

    /* get sides */
    i = &s->sides[SESSION_SIDE_INITIATOR];
    r = &s->sides[SESSION_SIDE_RESPONDER];

    /* event callback */
    if(event_cb != NULL) {
        event_cb(s, SESSION_EVENT_REDIRECT);
    }

    /* set SPN */
    s->spn = msg.hmsg_redirect.id.spn;

    /* get my ID */
    if(!crypto_get_id(s->spn, &i->id)) {
        return false;
    }

    /* copy peers ID */
    memcpy(&r->id, &msg.hmsg_redirect.id, sizeof(iasp_identity_t));

    /* find session for obtained redirection */
    if((redirect = iasp_session_by_peer(&msg.hmsg_redirect.tp_address)) == NULL) {
        /* establish new session if there is no previously established */
        debug_log("Cannot find session for redirect address.\n");
        /* discard const qualifier for private usage */
        s->redirect = (iasp_session_t *)iasp_session_start(&s->pctx.addr, &msg.hmsg_redirect.tp_address);
        if(s->redirect == NULL) {
            debug_log("Cannot create redirect session.\n");
            return false;
        }
    }
    else {
        streambuf_t *keyreq;
        iasp_mgmt_req_session_t *m = &msg.mgmt_req;

        /* save redirection */
        s->redirect = redirect;
        debug_log("Redirecting session %p via %p.\n", s, redirect);

        /* prepare for key request */
        iasp_reset_message();
        iasp_proto_reset_payload();
        keyreq = iasp_proto_get_payload_sb();

        /* add peer address */
        memcpy(&m->peer_address, &s->pctx.peer, sizeof(iasp_address_t));

        /* check if my address is needed */
        if(!iasp_network_address_equal(&s->pctx.addr, &s->redirect->pctx.addr)) {
            m->has_my_address = true;
            memcpy(&m->my_address, &s->pctx.addr, sizeof(iasp_address_t));
        }

        /* generate SPI from previously generated NONCE */
        memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
        memcpy(&m->spi, &i->spi, sizeof(iasp_spi_t));

        /* send key request */
        return iasp_encode_mgmt_req_session(keyreq, m) && iasp_session_send_mgmt(s->redirect, keyreq, false);
    }

    return true;
}


static iasp_session_t *iasp_session_by_peer(const iasp_address_t * const peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        iasp_session_t *s = &sessions[i];

        /* skip inactive sessions */
        if(!s->active) {
            continue;
        }

        /* check peer address */
        if(iasp_network_address_equal(&s->pctx.peer, peer)) {
            return s;
        }
    }

    /* nothing found */
    return NULL;
}


static iasp_session_t *iasp_session_by_peer_ip(const iasp_address_t * const peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        iasp_session_t *s = &sessions[i];

        /* skip inactive sessions */
        if(!s->active) {
            continue;
        }

        /* compare IP addresses */
        if(memcmp(iasp_network_address_ip(&s->pctx.peer), iasp_network_address_ip(peer), sizeof(iasp_ip_t)) == 0) {
            return s;
        }
    }

    /* nothing found */
    return NULL;
}

static iasp_session_t *iasp_session_by_address_pair(const iasp_address_t * const myaddress, const iasp_address_t * const peer)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        iasp_session_t *s = &sessions[i];

        /* skip inactive sessions */
        if(!s->active) {
            continue;
        }

        /* compare IP addresses */
        if(iasp_network_address_equal(&s->pctx.addr, myaddress) && iasp_network_address_equal(&s->pctx.peer, peer)) {
            return s;
        }
    }

    /* nothing found */
    return NULL;
}


static iasp_session_t *iasp_session_by_child(tp_child_session_t * child)
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        iasp_session_t *s = &sessions[i];
        iasp_tpdata_t *tpd = s->aux;

        /* tpd not set */
        if(tpd == NULL) {
            continue;
        }

        /* skip inactive sessions */
        if(!s->active) {
            continue;
        }

        /* compare child */
        if(tpd->child == child) {
            return s;
        }
    }

    /* nothing found */
    return NULL;
}

static bool iasp_handler_mgmt_req(iasp_session_t * const s, streambuf_t * const sb)
{
    iasp_session_t *session_responder;
    iasp_tpdata_t *tpdi, *tpdr;
    iasp_spn_code_t spn;
    tp_child_session_t *child;
    streambuf_t *keyinstall;

    /* assert TP role */
    assert(role == IASP_ROLE_TP);

    /* decode message */
    if(!iasp_decode_mgmt_req_session(sb, &msg.mgmt_req)) {
        debug_log("Cannot decode session request message.\n");
        return false;
    }

    /* find session for peer */
    session_responder = iasp_session_by_peer_ip(&msg.mgmt_req.peer_address);
    if(session_responder == NULL) {
        if(!iasp_send_status(s, IASP_STATUS_ERROR)) {
            debug_log("Cannot send error message to peer.\n");
        }
        debug_log("Cannot find responder session.\n");
        return false;
    }

    /* extract TP data */
    tpdi = (iasp_tpdata_t *)s->aux;
    tpdr = (iasp_tpdata_t *)session_responder->aux;

    /* choose SPN for session */
    spn = security_choose_spn2(&tpdi->ids, &tpdr->ids);
    if(spn == IASP_SPN_NONE || spn == IASP_SPN_MAX) {
        if(!iasp_send_status(s, IASP_STATUS_ERROR)) {
            debug_log("Cannot send error message to peer.\n");
        }
        debug_log("Cannot find matching SPN for child session.\n");
        return false;
    }
    debug_log("SPN for child session chosen: ");
    debug_print_spn(spn);
    debug_newline();

    /* allocate child session data */
    iasp_tpdata_new_child(tpdr);
    child = tpdi->child = tpdr->child;
    child->spn = spn;

    /* generate session data */
    crypto_gen_key(spn, &child->sides[SESSION_SIDE_INITIATOR].key);
    crypto_gen_key(spn, &child->sides[SESSION_SIDE_RESPONDER].key);
    memcpy(&child->sides[SESSION_SIDE_INITIATOR].spi, &msg.mgmt_req.spi, sizeof(iasp_spi_t));
    memset(&child->sides[SESSION_SIDE_RESPONDER].spi, 0, sizeof(iasp_spi_t));
    {
        const iasp_address_t *addr = msg.mgmt_req.has_my_address ?
                &msg.mgmt_req.my_address : &s->pctx.peer;

        memcpy(&child->sides[SESSION_SIDE_INITIATOR].addr, addr, sizeof(iasp_address_t));
    }
    memcpy(&child->sides[SESSION_SIDE_RESPONDER].addr, &msg.mgmt_req.peer_address, sizeof(iasp_address_t));
    memcpy(&child->sides[SESSION_SIDE_INITIATOR].id, crypto_id_by_spn(spn, &tpdi->ids), sizeof(iasp_identity_t));
    memcpy(&child->sides[SESSION_SIDE_RESPONDER].id, crypto_id_by_spn(spn, &tpdr->ids), sizeof(iasp_identity_t));
    crypto_gen_salt(&child->salt);

    /* prepare install session message */
    iasp_reset_message();
    iasp_proto_reset_payload();
    keyinstall = iasp_proto_get_payload_sb();

    /* fill key install info */
    {
        iasp_mgmt_install_session_t *m = &msg.mgmt_install;
        size_t keysize = child->sides[SESSION_SIDE_INITIATOR].key.keysize;

        /* set initiator ID and SPI */
        memcpy(&m->peer_id, &child->sides[SESSION_SIDE_INITIATOR].id, sizeof(iasp_identity_t));
        memcpy(&m->peer_spi, &child->sides[SESSION_SIDE_INITIATOR].spi, sizeof(iasp_spi_t));

        /* set skey data */
        m->skey.spn = spn;
        m->skey.keylen = keysize;
        memcpy(&m->skey.salt, &child->salt, sizeof(iasp_salt_t));
        memcpy(m->skey.ikey, child->sides[SESSION_SIDE_INITIATOR].key.keydata, keysize);
        memcpy(m->skey.rkey, child->sides[SESSION_SIDE_RESPONDER].key.keydata, keysize);

        /* set peer address */
        memcpy(&m->peer_address, &child->sides[SESSION_SIDE_INITIATOR].addr, sizeof(iasp_address_t));

        /* set your address if needed */
        if(!iasp_network_address_equal(&child->sides[SESSION_SIDE_RESPONDER].addr, &session_responder->pctx.peer)) {
            m->has_your_address = true;
            memcpy(&m->your_address, &child->sides[SESSION_SIDE_RESPONDER].addr, sizeof(iasp_address_t));
        }
    }

    /* send key install message */
    return iasp_encode_mgmt_install_session(keyinstall, &msg.mgmt_install) &&
            iasp_session_send_mgmt(session_responder, keyinstall, false);
}


static bool iasp_handler_mgmt_install(iasp_session_t * const s, streambuf_t * const sb)
{
    iasp_session_t * peer_session;
    iasp_address_t * my_address;
    iasp_session_side_data_t *i, *r;
    streambuf_t * reply;

    if(!iasp_decode_mgmt_install_session(sb, &msg.mgmt_install)) {
        debug_log("Failed to decode session install message.\n");
        return false;
    }

    debug_log("Received session install message.\n");

    /* determine your address for new session */
    my_address = msg.mgmt_install.has_your_address ? &msg.mgmt_install.your_address : &s->pctx.addr;

    /* find peer session */
    peer_session = iasp_session_by_address_pair(my_address, &msg.mgmt_install.peer_address);

    /* if session cannot be found - create new one */
    if(peer_session == NULL) {
        peer_session = iasp_session_new(my_address, &msg.mgmt_install.peer_address);
        if(peer_session == NULL) {
            debug_log("Failed to create new session.\n");
            return false;
        }
    }
    else {
        debug_log("Found session: %p.\n", peer_session);
    }

    /* extract side data */
    i = &peer_session->sides[SESSION_SIDE_INITIATOR];
    r = &peer_session->sides[SESSION_SIDE_RESPONDER];

    /* fill session info */
    {
        size_t keysize;

        /* save SPN */
        peer_session->spn = msg.mgmt_install.peer_id.spn;

        /* get proper key size */
        keysize = spn_get_key_size(peer_session->spn);

        /* get my id */
        crypto_get_id(peer_session->spn, &peer_session->sides[peer_session->side].id);

        /* set peer's ID */
        {
            iasp_identity_t *peerid;
            peerid = peer_session->side == SESSION_SIDE_INITIATOR ? &r->id : &i->id;
            memcpy(peerid, &msg.mgmt_install.peer_id, sizeof(iasp_identity_t));
        }

        /* set SALT */
        memcpy(&peer_session->salt, &msg.mgmt_install.skey.salt, sizeof(iasp_salt_t));

        /* set keys */
        i->key.spn = r->key.spn = peer_session->spn;
        i->key.keysize = r->key.keysize = keysize;
        memcpy(i->key.keydata, msg.mgmt_install.skey.ikey, keysize);
        memcpy(r->key.keydata, msg.mgmt_install.skey.rkey, keysize);

        /* set SPIs */
        if(peer_session->side == SESSION_SIDE_RESPONDER) {
            memcpy(i->spi.spidata, &msg.mgmt_install.peer_spi, sizeof(iasp_spi_t));
            memcpy(r->spi.spidata, r->nonce.data + 2, sizeof(iasp_spi_t));
        }
        else {
            memcpy(r->spi.spidata, &msg.mgmt_install.peer_spi, sizeof(iasp_spi_t));
            memcpy(i->spi.spidata, i->nonce.data + 2, sizeof(iasp_spi_t));
        }
    }

    /* prepare reply */
    iasp_reset_message();
    iasp_proto_reset_payload();
    reply = iasp_proto_get_payload_sb();

    switch(peer_session->side) {
        case SESSION_SIDE_RESPONDER:
            /* reply with SPI */
            memcpy(&msg.mgmt_spi.spi, &r->spi, sizeof(iasp_spi_t));
            s->pctx.msg_type = IASP_MSG_MGMT;
            if(!(iasp_encode_mgmt_spi(reply, &msg.mgmt_spi) &&
                    iasp_session_send_mgmt(s, reply, true))){
                return false;
            }
            break;

        case SESSION_SIDE_INITIATOR:
            if(!iasp_send_status(s, IASP_STATUS_OK)) {
                return false;
            }
            break;

        default:
            abort();
    }

    /* mark as established */
    peer_session->established = true;

    /* event notify */
    if(event_cb != NULL) {
        event_cb(peer_session, SESSION_EVENT_ESTABLISHED);
    }

    return true;
}


static bool iasp_handler_mgmt_spi(iasp_session_t * const s, streambuf_t * const sb)
{
    iasp_tpdata_t *tpd;
    streambuf_t *keyinstall;
    tp_child_session_t *child;
    iasp_session_t *session_initiator;

    assert(role == IASP_ROLE_TP);

    if(!iasp_decode_mgmt_spi(sb, &msg.mgmt_spi)) {
        debug_log("Cannot decode SPI message.\n");
        return false;
    }

    /* TODO: sanity checks */

    /* set missing responder SPI */
    tpd = s->aux;
    child = tpd->child;
    memcpy(&tpd->child->sides[SESSION_SIDE_RESPONDER].spi, &msg.mgmt_spi.spi, sizeof(iasp_spi_t));

    /* reset child infomation */
    tpd->child = NULL;

    /* prepare install for initiator */
    iasp_reset_message();
    iasp_proto_reset_payload();
    keyinstall = iasp_proto_get_payload_sb();

    /* find initiator session */
    session_initiator = iasp_session_by_child(child);
    if(session_initiator == NULL) {
        debug_log("Cannot find initiator for child session.\n");
        return false;
    }
    tpd = session_initiator->aux;

    /* fill key install info */
    {
        iasp_mgmt_install_session_t *m = &msg.mgmt_install;
        size_t keysize = child->sides[SESSION_SIDE_INITIATOR].key.keysize;

        /* set initiator ID and SPI */
        memcpy(&m->peer_id, &child->sides[SESSION_SIDE_RESPONDER].id, sizeof(iasp_identity_t));
        memcpy(&m->peer_spi, &child->sides[SESSION_SIDE_RESPONDER].spi, sizeof(iasp_spi_t));

        /* set skey data */
        m->skey.spn = child->spn;;
        m->skey.keylen = keysize;
        memcpy(&m->skey.salt, &child->salt, sizeof(iasp_salt_t));
        memcpy(m->skey.ikey, child->sides[SESSION_SIDE_INITIATOR].key.keydata, keysize);
        memcpy(m->skey.rkey, child->sides[SESSION_SIDE_RESPONDER].key.keydata, keysize);

        /* set peer address */
        memcpy(&m->peer_address, &child->sides[SESSION_SIDE_RESPONDER].addr, sizeof(iasp_address_t));

        /* set your address if needed */
        if(!iasp_network_address_equal(&child->sides[SESSION_SIDE_INITIATOR].addr, &session_initiator->pctx.peer)) {
            m->has_your_address = true;
            memcpy(&m->your_address, &child->sides[SESSION_SIDE_INITIATOR].addr, sizeof(iasp_address_t));
        }
    }

    /* encode and send */
    if(!(iasp_encode_mgmt_install_session(keyinstall, &msg.mgmt_install) &&
            iasp_session_send_mgmt(session_initiator, keyinstall, false))) {
        debug_log("Cannot send key install to the initiator.\n");
        return false;
    }

    /* TODO: destroy child session information */
    tpd->child = NULL;

    return true;
}


static bool iasp_send_status(iasp_session_t * const s, iasp_status_t status)
{
    streambuf_t *rsb;

    iasp_reset_message();
    iasp_proto_reset_payload();
    rsb = iasp_proto_get_payload_sb();

    msg.mgmt_status.status = status;

    return iasp_encode_mgmt_status(rsb, &msg.mgmt_status) &&
            iasp_session_send_mgmt(s, rsb, true);
}


static bool iasp_handler_mgmt_token(iasp_session_t * const s, streambuf_t * const sb)
{
    if(!iasp_decode_mgmt_token(sb, &msg.mgmt_token_t)) {
        debug_log("Cannot decode token message.\n");
        return false;
    }

    s->token = msg.token;
    return iasp_send_status(s, IASP_STATUS_OK);
}


static bool iasp_handler_mgmt_status(iasp_session_t * const s, streambuf_t * const sb)
{
    if(!iasp_decode_mgmt_status(sb, &msg.mgmt_status)) {
        debug_log("Cannot decode status message.\n");
        return false;
    }

    return true;
}


static bool iasp_session_send_mgmt(iasp_session_t * const s, streambuf_t * payload, bool answer)
{
    return iasp_session_send_msg(s, payload, IASP_MSG_MGMT, answer, true);
}


static bool iasp_session_send_hmsg(iasp_session_t * const s, streambuf_t * payload, bool answer)
{
    return iasp_session_send_msg(s, payload, IASP_MSG_HANDSHAKE, answer, false);
}


static void iasp_session_get_aad(iasp_session_t * const s, binbuf_t *bbaad)
{
    iasp_address_t *ia, *ra;
    static uint8_t aad[2*sizeof(iasp_ip_t) + sizeof(uint8_t)];

    bbaad->size = sizeof(aad);
    bbaad->buf = aad;
    if(s->side == SESSION_SIDE_INITIATOR) {
        ia = &s->pctx.addr;
        ra = &s->pctx.peer;
    }
    else {
        ra = &s->pctx.addr;
        ia = &s->pctx.peer;
    }

    memcpy(aad, iasp_network_address_ip(ia), sizeof(iasp_ip_t));
    memcpy(aad + sizeof(iasp_ip_t), iasp_network_address_ip(ra), sizeof(iasp_ip_t));
    iasp_proto_put_outer_hdr(aad + 2*sizeof(iasp_ip_t), true, s->pctx.pv, s->spn);
    debug_log("AAD: ");
    debug_print_binary(aad, sizeof(aad));
    debug_newline();
}


static void iasp_session_get_iv(iasp_session_t *s, binbuf_t *bbiv, bool output)
{
    uint32_t seq;
    static uint8_t iv[sizeof(iasp_nonce_t) + 2*sizeof(iasp_spi_t) + sizeof(uint32_t)];
    uint8_t *piv = iv;

    /* zero IV buffer */
    memset(iv, 0, sizeof(iv));

    /* prepare bb */
    bbiv->size = sizeof(iv);
    bbiv->buf = iv;

    /* copy SALT */
    memcpy(piv, s->salt.saltdata, sizeof(iasp_salt_t));
    piv += sizeof(iasp_salt_t);

    /* copy SPIs */
    memcpy(piv, &s->sides[SESSION_SIDE_INITIATOR].spi, sizeof(iasp_spi_t));
    memcpy(piv + sizeof(iasp_spi_t), &s->sides[SESSION_SIDE_RESPONDER].spi, sizeof(iasp_spi_t));
    piv += 2*sizeof(iasp_spi_t);

    /* copy sequence */
    seq = htonl(output ? s->pctx.output_seq : s->pctx.input_seq);
    memcpy(piv, (uint8_t *)&seq, sizeof(seq));
    debug_log("IV: ");
    debug_print_binary(iv, sizeof(iv));
    debug_newline();
}


static bool iasp_session_send_msg(iasp_session_t * const s, streambuf_t * payload, iasp_msg_type_t mt, bool answer, bool encrypted)
{
    bool result = false;

    /* set answer and pn */
    s->pctx.answer = answer;
    if(!answer) {
        iasp_proto_bump_pn(&s->pctx);
    }

    /* set message type */
    s->pctx.msg_type = mt;

    /* set encrypt flag and encrypt if needed */
    s->pctx.encrypted = encrypted;
    if(encrypted) {
        binbuf_t bbaad, bbiv;

        debug_log("Encrypting message.\n");

        /* check if there is a space for the tag */
        if(payload->max_size - payload->size < IASP_CRYPTO_TAG_LENGTH) {
            debug_log("Not enough space to encrypt message.\n");
            return false;
        }

        /* prepare AAD data */
        iasp_session_get_aad(s, &bbaad);

        /* prepare IV data */
        iasp_session_get_iv(s, &bbiv, true);

        /* set outgoing spi */
        s->pctx.output_spi = s->sides[s->side].spi;

        /* encrypt */
        {
            binbuf_t bbp;
            iasp_key_t *key;

            /* setup plaintext bb */
            bbp.buf = payload->data;
            bbp.size = payload->size;

            /* get key */
            key = &s->sides[s->side].key;

            /* do actual encryption */
            if(!crypto_encrypt(s->spn, &bbp, &bbaad, &bbiv, key->keydata, &bbp)) {
                debug_log("Failed to encrypt payload.\n");
                return false;
            }

            /* fix payload sb to cover tag */
            payload->size += IASP_CRYPTO_TAG_LENGTH;
        }
    }

    if(!iasp_proto_send(&s->pctx, payload)) {
        goto error;
    }

    result = true;
error:
    /* fix sequence */
    if(encrypted) {
        /* increment sequence */
        payload->size -= IASP_CRYPTO_TAG_LENGTH;
        s->pctx.output_seq += payload->size / 16;
        if(payload->size % 16) {
            s->pctx.output_seq += 1;
        }
    }

    return result;
}


static bool iasp_session_decrypt_msg(iasp_session_t * const s, streambuf_t * const payload)
{
    binbuf_t bbaad, bbiv;

    debug_log("Decrypting message.\n");

    if(!s->established) {
        debug_log("Session is not established.\n");
        return false;
    }

    /* prepare AAD data */
    iasp_session_get_aad(s, &bbaad);

    /* prepare IV data */
    iasp_session_get_iv(s, &bbiv, false);

    /* decrypt message */
    {
        binbuf_t p;
        iasp_session_side_t peer_side = s->side == SESSION_SIDE_INITIATOR ? SESSION_SIDE_RESPONDER : SESSION_SIDE_INITIATOR;

        p.buf = payload->data;
        p.size = payload->size;

        /* decrypt and remove tag */
        if(!crypto_decrypt(s->spn, &p, &bbaad, &bbiv, s->sides[peer_side].key.keydata, &p)) {
            return false;
        }
        payload->size -= IASP_CRYPTO_TAG_LENGTH;
    }

    return true;
}


bool iasp_session_send_userdata(iasp_session_t *s, const uint8_t *data, const size_t datasize)
{
    streambuf_t *sb;

    if(!s->established) {
        debug_log("Error, session is not established.\n");
        return false;
    }

    /* prepare for message */
    iasp_proto_reset_payload();
    sb = iasp_proto_get_payload_sb();
    streambuf_write(sb, data, datasize);

    return iasp_session_send_msg(s, sb, IASP_MSG_USER, false, true);
}


bool iasp_session_terminate(iasp_session_t * const s)
{
    streambuf_t *sb;

    debug_log("Terminating session: %p\n", s);

    /* prepare message buffer */
    iasp_reset_message();
    iasp_proto_reset_payload();
    sb = iasp_proto_get_payload_sb();

    /* init terminate */
    iasp_encode_mgmt_terminate(sb);

    /* send message */
    if(!iasp_session_send_mgmt(s, sb, false)) {
        return false;
    }

    /* mark as inactive */
    /* TODO: proper destroy */
    /* TODO: wait for reply */
    s->active = false;

    return true;
}


void iasp_session_destroy()
{
    unsigned int i;

    for(i = 0; i < IASP_CONFIG_MAX_SESSIONS; ++i) {
        if(!sessions[i].active) {
            continue;
        }
        iasp_session_terminate(&sessions[i]);
    }
}


static bool iasp_handler_mgmt_terminate(iasp_session_t * const s, streambuf_t * const sb)
{
    debug_log("Terminating session: %p\n", s);

    if(!s->established) {
        return false;
    }

    s->active = false;
    return true;
}
