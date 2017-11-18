#ifndef __IASP_TP_H__
#define __IASP_TP_H__

#include "crypto.h"
#include "ffd.h"
#include "types.h"


typedef struct {
    /* FFD data first */
    iasp_ffddata_t ffd;

    /* TP specific data */
    iasp_ids_t ids;
} iasp_tpdata_t;


/* init and destroy */
void iasp_tpdata_init(iasp_tpdata_t **this);
void iasp_tpdata_destroy(iasp_tpdata_t **this);

/* set data */
void iasp_tpdata_set_ids(iasp_tpdata_t * const this, const iasp_ids_t * const ids);


#endif
