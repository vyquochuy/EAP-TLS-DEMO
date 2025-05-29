#include "auth_server.h"
#include "authenticator.h"
#include <iostream>
#include <openssl/pem.h>
#include <iomanip>

void AuthenticationServer::receive(const Message& message, EAPAuthenticator* authenticator) {
    std::cout << "[AuthServer] Received message: " << message.type << "\n";

    if (message.type == EAP_RESPONSE_IDENTITY) {
        identity = message.data;
        std::cout << "[AuthServer] Client identity received: " << identity << "\n";
        std::cout << "[AuthServer] Sending TLS-Start request to initiate handshake\n";
        authenticator->send_to_peer({ EAP_REQUEST_TLS_START, "" });
    }
    else if (message.type == EAP_TLS_CLIENT_HELLO) {
        std::cout << "[AuthServer] Received client certificate, parsing and verifying...\n";
        std::cout << "[AuthServer] Client Certificate received:\n" << message.data << "\n";

        peer_cert = nullptr;
        BIO* bio = BIO_new_mem_buf(message.data.c_str(), message.data.size());
        PEM_read_bio_X509(bio, &peer_cert, NULL, NULL);
        BIO_free(bio);

        if (peer_cert && verify_cert(peer_cert, ca_cert)) {
            std::cout << "[AuthServer] Peer certificate verification SUCCESS\n";
            std::cout << "[AuthServer] Certificate chain validation passed\n";

            std::string server_cert_pem = serialize_cert(cert);
            std::cout << "[AuthServer] Sending server certificate to client\n";
            std::cout << "[AuthServer] Server Certificate being sent:\n" << server_cert_pem << "\n";

            authenticator->send_to_peer({ EAP_TLS_SERVER_HELLO, server_cert_pem });
        }
        else {
            std::cout << "[AuthServer] Peer certificate verification FAILED\n";
            std::cout << "[AuthServer] Certificate chain validation failed or certificate is invalid\n";
            authenticator->send_to_peer({ EAP_FAILURE, "Invalid peer cert" });
        }
    }
    else if (message.type == EAP_TLS_PREMASTER_SECRET) {
        std::cout << "[AuthServer] Received encrypted Pre-Master Secret\n";
        std::cout << "[AuthServer] Encrypted PMS size: " << message.data.size() << " bytes\n";

        // Decrypt the pre-master secret with server's private key
        std::string decrypted_pms = decrypt_with_key(message.data, key);

        if (!decrypted_pms.empty() && decrypted_pms.size() == 48) {
            std::cout << "[AuthServer] Pre-Master Secret decrypted successfully\n";
            std::cout << "[AuthServer] Decrypted PMS (hex): ";
            for (size_t i = 0; i < decrypted_pms.size(); i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)decrypted_pms[i];
                if (i % 16 == 15) std::cout << "\n[AuthServer]                        ";
            }
            std::cout << std::dec << "\n";

            // Generate session key (same way as peer)
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256((const unsigned char*)decrypted_pms.c_str(), decrypted_pms.size(), hash);

            std::cout << "[AuthServer] Session Key generated (SHA256 of PMS):\n";
            std::cout << "[AuthServer] Session Key (hex): ";
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                if (i % 16 == 15) std::cout << "\n[AuthServer]                       ";
            }
            std::cout << std::dec << "\n";

            std::cout << "[AuthServer] Authentication SUCCESS! TLS handshake completed\n";
            std::cout << "[AuthServer] Secure session established\n";
            authenticator->send_to_peer({ EAP_SUCCESS, "" });
        }
        else {
            std::cout << "[AuthServer] Failed to decrypt Pre-Master Secret or invalid size\n";
            std::cout << "[AuthServer] Expected size: 48 bytes, Got: " << decrypted_pms.size() << " bytes\n";
            authenticator->send_to_peer({ EAP_FAILURE, "Invalid pre-master secret" });
        }
    }
}