#include "tp.h"

#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>


void iasp_tpdata_init(iasp_tpdata_t **this)
{
    assert(this != NULL);

    if(*this == NULL) {
        *this = malloc(sizeof(iasp_tpdata_t));
    }

    memset(*this, 0, sizeof(iasp_tpdata_t));
}


void iasp_tpdata_destroy(iasp_tpdata_t ** const this)
{
    assert(this != NULL);

    if(*this != NULL) {
        free(*this);
        *this = NULL;
    }
}
