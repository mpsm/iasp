#ifndef __IASP_MESSAGE_H__
#define __IASP_MESSAGE_H__


#include <stdbool.h>


typedef enum {
    IASP_HMSG_INIT_HELLO = 1,
    IASP_HMSG_RESP_HELLO = 2,
    IASP_HMSG_INIT_AUTH = 3,
    IASP_HMSG_RESP_AUTH = 4,
    IASP_HMSG_REDIRECT = 5,
} iasp_handshake_msg_code_t;


typedef enum {
    IASP_MGMT_REQ = 1,
    IASP_MGMT_INSTALL = 2,
} iasp_mgmt_msg_code_t;


typedef struct {
    iasp_nonce_t            inonce;
    iasp_ids_t              ids;
} iasp_hmsg_init_hello_t;


typedef struct {
    iasp_nonce_t            inonce;
    iasp_nonce_t            rnonce;
    iasp_identity_t         id;
    iasp_session_flags_t    flags;
} iasp_hmsg_resp_hello_t;


typedef struct {
    iasp_nonce_t            inonce;
    iasp_nonce_t            rnonce;
    iasp_sig_t              sig;
    iasp_session_flags_t    flags;

    /* optional fields */
    iasp_pkey_t             dhkey;
    iasp_pkey_t             pkey;
    iasp_sig_t              oobsig;
    iasp_hint_t             hint;

    /* optional fields flags */
    bool                    has_dhkey;
    bool                    has_pkey;
    bool                    has_oobsig;
    bool                    has_hint;
} iasp_hmsg_init_auth_t;


typedef struct {
    iasp_nonce_t            inonce;
    iasp_nonce_t            rnonce;
    iasp_sig_t              sig;
    iasp_pkey_t             dhkey;

    /* optional fields */
    iasp_pkey_t             pkey;
    iasp_sig_t              oobsig;
    iasp_hint_t             hint;

    /* optional fields flags */
    bool                    has_pkey;
    bool                    has_oobsig;
    bool                    has_hint;
} iasp_hmsg_resp_auth_t;


typedef struct {
    iasp_identity_t         id;
    iasp_address_t          tp_address;
} iasp_hmsg_redirect_t;


typedef struct {
    iasp_spi_t              spi;
    iasp_address_t *        peer_address;
    iasp_address_t *        my_address;
    bool                    has_my_address;
} iasp_mgmt_req_session_t;


typedef struct {
    iasp_identity_t         peer_id;
    iasp_spi_t              peer_spi;
    iasp_address_t*         peer_address;
    iasp_address_t*         your_address;
    bool                    has_your_address;
} iasp_mgmt_install_session_t;


typedef union {
    /* handshake protocol */
    iasp_hmsg_init_hello_t  hmsg_init_hello;
    iasp_hmsg_resp_hello_t  hmsg_resp_hello;
    iasp_hmsg_init_auth_t   hmsg_init_auth;
    iasp_hmsg_resp_auth_t   hmsg_resp_auth;
    iasp_hmsg_redirect_t    hmsg_redirect;

    /* management protocol */
    iasp_mgmt_install_session_t mgmt_install;
    iasp_mgmt_req_session_t     mgmt_req;
} iasp_msg_storage_t;


#endif
