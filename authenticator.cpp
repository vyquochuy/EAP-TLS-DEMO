#include "authenticator.h"
#include <iostream>

void EAPAuthenticator::receive(const Message& message, EAPPeer* p) {
    std::cout << "[Authenticator] Received from Peer: " << message.type << "\n";
    peer = p;

    if (message.type == EAPOL_START) {
        std::cout << "[Authenticator] EAPOL-Start received, requesting client identity\n";
        peer->receive({ EAP_REQUEST_IDENTITY, "" }, this);
    }
    else if (message.type == EAP_RESPONSE_IDENTITY ||
        message.type == EAP_TLS_CLIENT_HELLO ||
        message.type == EAP_TLS_PREMASTER_SECRET) {
        std::cout << "[Authenticator] Forwarding message to Authentication Server\n";
        auth_server->receive(message, this);
    }
}

void EAPAuthenticator::send_to_peer(const Message& message) {
    std::cout << "[Authenticator] Sending to Peer: " << message.type << "\n";
    peer->receive(message, this);
}