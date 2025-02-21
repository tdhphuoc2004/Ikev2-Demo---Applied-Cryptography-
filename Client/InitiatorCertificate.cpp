#include "InitiatorCertificate.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


EVP_PKEY* generate_rsa_key(int key_size) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) {
        printf("Error creating key context\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Error initializing keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0) {
        printf("Error setting key size\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Error generating key\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Create a self-signed CA certificate
X509* create_ca_certificate(EVP_PKEY* pkey, int validity_days)
{
    X509* x509 = X509_new();
    X509_NAME* name;

    if (!x509) {
        printf("Error creating X.509 certificate.\n");
        return NULL;
    }

    X509_set_version(x509, 2); // X.509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // Set certificate validity
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), validity_days * 24 * 3600);

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject and issuer (self-signed CA)
    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"VN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"GROUP5", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"My Root CA", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Add CA basic constraints
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate with the private key
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        printf("Error signing CA certificate.\n");
        X509_free(x509);
        return NULL;
    }

    return x509;
}
