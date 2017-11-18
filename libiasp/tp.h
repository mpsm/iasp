#ifndef __IASP_TP_H__
#define __IASP_TP_H__

#include "crypto.h"
#include "ffd.h"
#include "types.h"


typedef struct {
    struct side_data {
        iasp_key_t      key;
        iasp_address_t  addr;
        iasp_spi_t      spi;
        iasp_identity_t id;
    }
    sides[SESSION_SIDE_COUNT];
    iasp_salt_t         salt;
} tp_child_session_t;


typedef struct {
    /* FFD data first */
    iasp_ffddata_t ffd;

    /* TP specific data */
    iasp_ids_t ids;
    tp_child_session_t *child;
} iasp_tpdata_t;


/* init and destroy */
void iasp_tpdata_init(iasp_tpdata_t **this);
void iasp_tpdata_destroy(iasp_tpdata_t **this);

/* set data */
void iasp_tpdata_set_ids(iasp_tpdata_t * const this, const iasp_ids_t * const ids);
void iasp_tpdata_new_child(iasp_tpdata_t * const this);

#endif
