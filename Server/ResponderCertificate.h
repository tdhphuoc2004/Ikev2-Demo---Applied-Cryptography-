#pragma once
#define X509Cert_Signature 4 

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

EVP_PKEY* generate_rsa_key(int keysize); 
X509* create_ca_certificate(EVP_PKEY* pkey, int validity_days); 
