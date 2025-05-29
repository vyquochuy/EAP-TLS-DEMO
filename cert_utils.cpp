#include "cert_utils.h"

EVP_PKEY* generate_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509* generate_cert(const std::string& subject_name, const std::string& issuer_name, EVP_PKEY* issuer_key, EVP_PKEY* subject_key, bool is_ca) {
    if (!issuer_key || !subject_key) {
        std::cerr << "Invalid keys provided for certificate generation.\n";
        return NULL;
    }

    X509* cert = X509_new();
    if (!cert) {
        std::cerr << "Failed to create new X509 certificate.\n";
        return NULL;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 năm

    X509_NAME* subject = X509_NAME_new();
    if (!subject) {
        std::cerr << "Failed to create new X509_NAME for subject.\n";
        X509_free(cert);
        return NULL;
    }
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char*)subject_name.c_str(), -1, -1, 0);
    X509_set_subject_name(cert, subject);
    X509_NAME_free(subject);

    X509_NAME* issuer = X509_NAME_new();
    if (!issuer) {
        std::cerr << "Failed to create new X509_NAME for issuer.\n";
        X509_free(cert);
        return NULL;
    }
    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC, (const unsigned char*)issuer_name.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, issuer);
    X509_NAME_free(issuer);

    X509_set_pubkey(cert, subject_key);

    if (is_ca) {
        // Cách 1: Sử dụng X509V3_EXT_conf_nid (đơn giản hơn)
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
        if (!ext) {
            std::cerr << "Failed to create X509 extension for CA.\n";
            X509_free(cert);
            return NULL;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // Thêm Key Usage extension cho CA
        X509_EXTENSION* key_usage_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (key_usage_ext) {
            X509_add_ext(cert, key_usage_ext, -1);
            X509_EXTENSION_free(key_usage_ext);
        }
    }

    if (!X509_sign(cert, issuer_key, EVP_sha256())) {
        std::cerr << "Failed to sign certificate.\n";
        X509_free(cert);
        return NULL;
    }

    return cert;
}

std::string serialize_key(EVP_PKEY* key) {
    if (!key) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string serialize_cert(X509* cert) {
    if (!cert) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    PEM_write_bio_X509(bio, cert);
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

bool verify_cert(X509* cert, X509* ca_cert) {
    if (!cert || !ca_cert) return false;

    X509_STORE* store = X509_STORE_new();
    if (!store) return false;

    X509_STORE_add_cert(store, ca_cert);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        return false;
    }

    X509_STORE_CTX_init(ctx, store, cert, NULL);
    int result = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return result == 1;
}

std::string encrypt_with_cert_pubkey(const std::string& data, X509* cert) {
    if (!cert || data.empty()) return "";

    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) return "";

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char*)data.c_str(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    unsigned char* encrypted = new unsigned char[outlen];
    if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, (const unsigned char*)data.c_str(), data.size()) <= 0) {
        delete[] encrypted;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return "";
    }

    std::string result((char*)encrypted, outlen);
    delete[] encrypted;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return result;
}

std::string decrypt_with_key(const std::string& ciphertext, EVP_PKEY* private_key) {
    if (!private_key || ciphertext.empty()) return "";

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) return "";

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    unsigned char* decrypted = new unsigned char[outlen];
    if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
        delete[] decrypted;
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::string result((char*)decrypted, outlen);
    delete[] decrypted;
    EVP_PKEY_CTX_free(ctx);
    return result;
}