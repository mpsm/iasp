#ifndef __IASP_TYPES__H__
#define __IASP_TYPES__H__


#include "config.h"

#include <stdint.h>
#include <stddef.h>


typedef enum {
    IASP_SPN_NONE = 0,
    IASP_SPN_128 = 1,
    IASP_SPN_256 = 2,

    /* sentinel */
    IASP_SPN_MAX,
} iasp_spn_code_t;


typedef enum {
    IASP_SIG_EC,
    IASP_SIG_HMAC,

    /* sentinel */
    IASP_SIG_MAX,
} iasp_sigtype_t;


typedef enum {
    SESSION_SIDE_INITIATOR,
    SESSION_SIDE_RESPONDER,

    /* counter */
    SESSION_SIDE_COUNT,
} iasp_session_side_t;


typedef enum {
    IASP_STATUS_OK = 0,
    IASP_STATUS_ERROR = 1,

    IASP_STATUS_MAX
} iasp_status_t;


typedef enum {
    IASP_ROLE_CD = 0,
    IASP_ROLE_FFD = 1,
    IASP_ROLE_TP = 2,

    /* sentinel */
    IASP_ROLE_MAX
} iasp_role_t;



typedef union {
    struct {
        unsigned char send_pkey:1;
        unsigned char oob_auth:1;
        unsigned char send_hint:1;
    } bits;
    uint8_t byte;
} iasp_session_flags_t;


typedef struct {
    iasp_spn_code_t spn;
    uint8_t data[IASP_CONFIG_IDENTITY_SIZE];
} iasp_identity_t;


typedef struct _iasp_spn_support {
    iasp_identity_t id;
    void *aux_data;

    struct _iasp_spn_support *next;
} iasp_spn_support_t;


typedef struct {
    uint8_t data[IASP_CONFIG_NONCE_SIZE];
} iasp_nonce_t;


typedef struct {
    uint8_t ipdata[16];
} iasp_ip_t;


typedef struct {
    iasp_spn_code_t spn;
    iasp_sigtype_t sigtype;
    size_t siglen;
    uint8_t sigdata[IASP_CONFIG_MAX_SIG_SIZE];
} iasp_sig_t;


typedef struct {
    unsigned int life_bytes;
    unsigned int life_seconds;
} iasp_kparam_t;


typedef struct {
    iasp_spn_code_t spn;
    size_t pkeylen;
    uint8_t pkeydata[IASP_CONFIG_MAX_PKEY_SIZE];
} iasp_pkey_t;


typedef struct {
    size_t hintlen;
    uint8_t hintdata[IASP_CONFIG_MAX_HINT_SIZE];
} iasp_hint_t;


#define IASP_MAX_IDS (2)
typedef struct {
    size_t id_count;
    iasp_identity_t id[IASP_MAX_IDS];
} iasp_ids_t;


#define IASP_SALT_SIZE (4)
typedef struct {
    uint8_t saltdata[IASP_SALT_SIZE];
} iasp_salt_t;


#define IASP_MAX_KEY_SIZE (32)
typedef struct {
    size_t keysize;
    iasp_spn_code_t spn;
    uint8_t keydata[IASP_MAX_KEY_SIZE];
} iasp_key_t;


/* network byte order */
typedef union {
    uint16_t spi;
    uint8_t spidata[sizeof(uint16_t)];
} iasp_spi_t;


typedef struct {
    void *aux;
} iasp_address_t;


typedef struct {
    iasp_spn_code_t spn;
    size_t keylen;
    iasp_salt_t salt;
    uint8_t ikey[IASP_MAX_KEY_SIZE];
    uint8_t rkey[IASP_MAX_KEY_SIZE];
} iasp_skey_t;


typedef uint32_t iasp_token_t;

#endif
