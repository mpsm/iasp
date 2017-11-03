#include "tp.h"

#include <assert.h>
#include <string.h>
#include <stddef.h>


void iasp_tpdata_init(iasp_tpdata_t * const this)
{
    assert(this != NULL);
    memset(this, 0, sizeof(iasp_tpdata_t));
}
