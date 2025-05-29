#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include "messages.h"
#include "auth_server.h"
#include "peer.h"

class EAPAuthenticator {
private:
    AuthenticationServer* auth_server;
    EAPPeer* peer;

public:
    EAPAuthenticator(AuthenticationServer* server) : auth_server(server), peer(nullptr) {}
    void receive(const Message& message, EAPPeer* p);
    void send_to_peer(const Message& message);
};

#endif // AUTHENTICATOR_H