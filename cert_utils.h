#ifndef CERT_UTILS_H
#define CERT_UTILS_H

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>
#include <string>
#include <iostream>

EVP_PKEY* generate_key();
X509* generate_cert(const std::string& subject_name, const std::string& issuer_name, EVP_PKEY* issuer_key, EVP_PKEY* subject_key, bool is_ca = false);
std::string serialize_key(EVP_PKEY* key);
std::string serialize_cert(X509* cert);
bool verify_cert(X509* cert, X509* ca_cert);
std::string encrypt_with_cert_pubkey(const std::string& data, X509* cert);
std::string decrypt_with_key(const std::string& ciphertext, EVP_PKEY* private_key);

#endif // CERT_UTILS_H