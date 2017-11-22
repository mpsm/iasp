#include "libiasp/debug.h"

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


static X509_STORE *cert_ctx = NULL;


bool pki_init()
{
    cert_ctx = X509_STORE_new();
    return cert_ctx != NULL;
}


bool pki_crl(const char *path)
{
    BIO *in = NULL;
    X509_CRL *crl;

    assert(path != NULL);

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        debug_log("PKI: Failed to open file: %s.\n", path);
        return false;
    }

    if (BIO_read_filename(in, path) <= 0) {
        debug_log("PKI: File %s open error %s.\n", path, strerror(errno));
    }

    crl = d2i_X509_CRL_bio(in, NULL);
    if(crl == NULL) {
        debug_log("Failed to load CRL from file %s.\n", path);
        return false;
    }

    X509_STORE_add_crl(cert_ctx, crl);
    BIO_free(in);

    return true;
}


bool pki_lookup(const char *cafile, const char *capath)
{
    X509_LOOKUP *lookup = NULL;

    if(cafile != NULL) {
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
        if(lookup == NULL) {
            return false;
        }
        if(!X509_LOOKUP_load_file(lookup, cafile, X509_FILETYPE_PEM)) {
            if(!X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT)) {
                debug_log("PKI: Error loading CA file.\n");
                return false;
            }
        }
    }

    if(capath != NULL) {
        lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
        if(lookup == NULL) {
            return false;
        }
        if(!X509_LOOKUP_add_dir(lookup, capath, X509_FILETYPE_PEM)) {
            if(!X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT)) {
                debug_log("PKI: Error loading CA path.\n");
                return false;
            }
        }
    }

    return true;
}
