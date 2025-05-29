#ifndef AUTH_SERVER_H
#define AUTH_SERVER_H

#include "messages.h"
#include "cert_utils.h"
#include <string>
#include <openssl/ssl.h>
class EAPAuthenticator;

class AuthenticationServer {
private:
    std::string name;
    X509* cert;
    EVP_PKEY* key;
    X509* ca_cert;
    X509* peer_cert;
    std::string identity;

public:
    AuthenticationServer(std::string n, X509* c, EVP_PKEY* k, X509* ca)
        : name(n), cert(c), key(k), ca_cert(ca), peer_cert(nullptr) {
    }

    void receive(const Message& message, EAPAuthenticator* authenticator);
};

#endif // AUTH_SERVER_H