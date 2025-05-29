#include "peer.h"
#include "authenticator.h"
#include <iostream>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iomanip>

void EAPPeer::start(EAPAuthenticator* authenticator) {
    std::cout << "[Peer] Starting EAP-TLS authentication process\n";
    std::cout << "[Peer] Sending EAPOL-Start message\n";
    authenticator->receive({ EAPOL_START, "" }, this);
}

void EAPPeer::receive(const Message& message, EAPAuthenticator* authenticator) {
    std::cout << "[Peer] Received message: " << message.type << "\n";

    if (message.type == EAP_REQUEST_IDENTITY) {
        std::cout << "[Peer] Responding with identity: " << name << "\n";
        authenticator->receive({ EAP_RESPONSE_IDENTITY, name }, this);
    }
    else if (message.type == EAP_REQUEST_TLS_START) {
        std::cout << "[Peer] Starting TLS handshake - sending client certificate\n";
        std::string cert_pem = serialize_cert(cert);
        std::cout << "[Peer] Client Certificate being sent:\n" << cert_pem << "\n";
        authenticator->receive({ EAP_TLS_CLIENT_HELLO, cert_pem }, this);
    }
    else if (message.type == EAP_TLS_SERVER_HELLO) {
        std::cout << "[Peer] Received server certificate, verifying...\n";
        std::cout << "[Peer] Server Certificate received:\n" << message.data << "\n";

        X509* server_cert = nullptr;
        BIO* bio = BIO_new_mem_buf(message.data.c_str(), message.data.size());
        PEM_read_bio_X509(bio, &server_cert, NULL, NULL);
        BIO_free(bio);

        if (verify_cert(server_cert, ca_cert)) {
            std::cout << "[Peer] Server certificate verification SUCCESS\n";

            // Generate pre-master secret
            unsigned char pre_master_secret[48];
            RAND_bytes(pre_master_secret, sizeof(pre_master_secret));

            std::cout << "[Peer] Generated Pre-Master Secret (48 bytes):\n";
            std::cout << "[Peer] Pre-Master Secret (hex): ";
            for (int i = 0; i < 48; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pre_master_secret[i];
                if (i % 16 == 15) std::cout << "\n[Peer]                              ";
            }
            std::cout << std::dec << "\n";

            // Encrypt pre-master secret with server's public key
            std::string encrypted_pms = encrypt_with_cert_pubkey(std::string((char*)pre_master_secret, 48), server_cert);
            std::cout << "[Peer] Pre-Master Secret encrypted with server's public key\n";
            std::cout << "[Peer] Encrypted PMS size: " << encrypted_pms.size() << " bytes\n";

            // Generate session key from pre-master secret
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(pre_master_secret, sizeof(pre_master_secret), hash);
            session_key = std::string((char*)hash, SHA256_DIGEST_LENGTH);

            std::cout << "[Peer] Session Key generated (SHA256 of PMS):\n";
            std::cout << "[Peer] Session Key (hex): ";
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                if (i % 16 == 15) std::cout << "\n[Peer]                     ";
            }
            std::cout << std::dec << "\n";

            std::cout << "[Peer] Sending encrypted Pre-Master Secret to server\n";
            authenticator->receive({ EAP_TLS_PREMASTER_SECRET, encrypted_pms }, this);
        }
        else {
            std::cout << "[Peer] Server certificate verification FAILED\n";
            authenticator->receive({ EAP_FAILURE, "Invalid server cert" }, this);
        }

        if (server_cert) {
            X509_free(server_cert);
        }
    }
    else if (message.type == EAP_SUCCESS) {
        std::cout << "[Peer] Authentication SUCCESS! EAP-TLS handshake completed\n";
        std::cout << "[Peer] Secure session established with session key\n";
    }
    else if (message.type == EAP_FAILURE) {
        std::cout << "[Peer] Authentication FAILURE: " << message.data << "\n";
    }
}