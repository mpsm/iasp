#ifndef __IASP_TYPES__H__
#define __IASP_TYPES__H__


#include "config.h"

#include <stdint.h>
#include <stddef.h>


typedef enum {
    IASP_ROLE_CD = 0,
    IASP_ROLE_FFD = 1,
    IASP_ROLE_TP = 2,

    /* sentinel */
    IASP_ROLE_MAX
} iasp_role_t;


typedef enum {
    IASP_SPN_NONE = 0,
    IASP_SPN_128 = 1,
    IASP_SPN_256 = 2,

    /* sentinel */
    IASP_SPN_MAX,
} iasp_spn_code_t;


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
    size_t siglen;
    uint8_t sigdata[IASP_CONFIG_MAX_SIG_SIZE];
} iasp_sig_t;


typedef struct {
    iasp_spn_code_t spn;
    uint8_t sigdata[IASP_CONFIG_MAX_HMAC_SIZE];
} iasp_hmac_t;


typedef struct {
    unsigned int life_bytes;
    unsigned int life_seconds;
} iasp_kparam_t;


typedef struct {
    iasp_spn_code_t spn;
    uint8_t pkeydata[IASP_CONFIG_MAX_PKEY_SIZE];
} iasp_pkey_t;


typedef struct {
    uint8_t hintdata[IASP_CONFIG_MAX_HINT_SIZE];
} iasp_hint_t;

#define IASP_MAX_IDS (2)

typedef struct {
    size_t id_count;
    iasp_identity_t id[IASP_MAX_IDS];
} iasp_ids_t;

#endif
