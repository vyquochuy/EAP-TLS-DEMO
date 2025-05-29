#ifndef PEER_H
#define PEER_H

#include "messages.h"
#include "cert_utils.h"
#include <string>

class EAPAuthenticator;

class EAPPeer {
private:
    std::string name;
    X509* cert;
    EVP_PKEY* key;
    X509* ca_cert;
    std::string session_key;

public:
    EAPPeer(std::string n, X509* c, EVP_PKEY* k, X509* ca)
        : name(n), cert(c), key(k), ca_cert(ca) {
    }

    void start(EAPAuthenticator* authenticator);
    void receive(const Message& message, EAPAuthenticator* authenticator);
};

#endif // PEER_H