#ifndef __IASP_MESSAGE_H__
#define __IASP_MESSAGE_H__


typedef enum {
    IASP_HMSG_INIT_HELLO = 1,
    IASP_HMSG_RESP_HELLO = 2,
    IASP_HMSG_INIT_AUTH = 3,
    IASP_HMSG_RESP_AUTH = 4,
    IASP_HMSG_REDIRECT = 5,
    IASP_HMSG_SESSION_AUTH = 6,
    IASP_HMSG_HINT_REQ = 7,
    IASP_HMSG_HINT_RESP = 8,
} iasp_handshake_msg_code_t;


typedef struct {
    iasp_ids_t ids;
} iasp_hmsg_init_hello_t;


typedef struct {
    iasp_identity_t id;
    iasp_nonce_t rnonce;
} iasp_hmsg_resp_hello_t;


typedef enum {
    IASP_SIG_EC,
    IASP_SIG_HMAC,
} iasp_sig_type_t;


typedef struct {
    iasp_sig_type_t sigtype;
    union {
        iasp_ecsig_t ecsig;
        iasp_hmac_t hmac;
    };
} iasp_sig_t;


typedef struct {
    iasp_nonce_t inonce;
    iasp_nonce_t rnonce;
    iasp_ecsig_t sig;
    bool         has_pkey;
    iasp_pkey_t  pkey;
} iasp_hmsg_init_auth_t;


typedef struct {
    iasp_pkey_t   pkey;
    iasp_kparam_t kparam;
    bool          has_hmac;
    iasp_sig_t    sig;
} iasp_hmsg_resp_auth_t;


typedef struct {
    iasp_identity_t id;
    iasp_ip_t       ip;
} iasp_hmsg_redirect_t;


typedef struct {
    iasp_ecsig_t sig;
} iasp_hmsg_session_auth_t;


typedef struct {
    iasp_identity_t id;
} iasp_hmsg_hint_req_t;


typedef struct {
    iasp_hint_t hint;
} iasp_hmsg_hint_resp_t;


typedef union {
    iasp_hmsg_init_hello_t   hmsg_init_hello;
    iasp_hmsg_resp_hello_t   hmsg_resp_hello;
    iasp_hmsg_init_auth_t    hmsg_init_auth;
    iasp_hmsg_resp_auth_t    hmsg_resp_auth;
    iasp_hmsg_redirect_t     hmsg_redirect;
    iasp_hmsg_session_auth_t hmsg_session_auth;
    iasp_hmsg_hint_req_t     hmsg_hint_req;
    iasp_hmsg_hint_resp_t    hmsg_hint_resp;
} iasp_msg_storage_t;


#endif
