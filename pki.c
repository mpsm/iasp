#include "libiasp/debug.h"
#include "libiasp/types.h"
#include "libiasp/security.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto-openssl.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static X509_STORE *cert_ctx = NULL;
typedef struct _pki_cert {
    X509 *x509;
    iasp_identity_t id;
    iasp_pkey_t pkey;
    struct _pki_cert *next;
} pki_cert_t;
pki_cert_t *pki_cert_head = NULL;
pki_cert_t *pki_cert_last = NULL;


/* private methods */
static BIO *pki_read_file(const char *filename);


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

    if((in = pki_read_file(path)) == NULL) {
        return false;
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


static BIO *pki_read_file(const char *filename)
{
    BIO *in = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        debug_log("PKI: Failed to open file: %s.\n", filename);
        return NULL;
    }

    if (BIO_read_filename(in, filename) <= 0) {
        debug_log("PKI: File %s open error %s.\n", filename, strerror(errno));
        return NULL;
    }

    return in;
}


bool pki_load_cert(const char *filepath)
{
    BIO *in;
    pki_cert_t *new;
    EVP_PKEY *evppkey;
    X509_STORE_CTX *sctx;

    /* read file */
    new = malloc(sizeof(pki_cert_t));
    if((in = pki_read_file(filepath)) == NULL) {
        return false;
    }

    /* read x509 file */
    new->x509 = d2i_X509_bio(in, NULL);
    if(new->x509 == NULL) {
        debug_log("PKI: Failed to load certificate.\n");
        return false;
    }

    /* extract public key and id */
    evppkey = X509_get_pubkey(new->x509);
    if(evppkey == NULL) {
        return false;
    }
    if(!crypto_openssl_extract_key(&new->pkey, &new->id, evppkey)) {
        debug_log("PKI: Cannot extract key from certificate.\n");
        return false;
    }
    sctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(sctx, cert_ctx, new->x509, NULL);
    if(!X509_verify_cert(sctx)) {
        debug_log("PKI: Cannot validate certificate.\n");
        return false;
    }
    debug_log("Certificate is valid!\n");

    /* add pkey to database */
    iasp_peer_add_pkey(&new->pkey);

    /* link structure */
    new->next = NULL;
    if(pki_cert_head == NULL) {
        pki_cert_head = new;
    }

    if(pki_cert_last != NULL) {
        pki_cert_last->next = new;
    }
    pki_cert_last = new;

    BIO_free(in);

    return true;
}

