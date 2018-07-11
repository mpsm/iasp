#ifndef __PKI_H__
#define __PKI_H__

#include <stdbool.h>

bool pki_init();
bool pki_crl(const char *path);
bool pki_lookup(const char *cafile, const char *capath);
bool pki_load_cert(const char *filepath);

#endif
