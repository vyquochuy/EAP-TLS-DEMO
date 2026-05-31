#include "peer.h"
#include "authenticator.h"
#include "auth_server.h"
#include "cert_utils.h"
#include <iostream>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    // Khởi tạo OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "EAP-TLS Authentication Simulation\n";

    try {
        std::cout << "\n=== STEP 1: GENERATING CA (CERTIFICATE AUTHORITY) ===\n";

        // Tạo CA key
        EVP_PKEY* ca_key = generate_key();
        if (!ca_key) {
            std::cerr << "Failed to generate CA key.\n";
            return 1;
        }
        std::cout << "✓ CA Private Key generated successfully\n";
        std::cout << "CA Private Key:\n" << serialize_key(ca_key) << "\n";

        // Tạo CA certificate
        X509* ca_cert = generate_cert("CA", "CA", ca_key, ca_key, true);
        if (!ca_cert) {
            std::cerr << "Failed to generate CA certificate.\n";
            EVP_PKEY_free(ca_key);
            return 1;
        }
        std::cout << "✓ CA Certificate generated successfully\n";
        std::cout << "CA Certificate:\n" << serialize_cert(ca_cert) << "\n";

        std::cout << "\n=== STEP 2: GENERATING SERVER CREDENTIALS ===\n";

        // Tạo server key
        EVP_PKEY* server_key = generate_key();
        if (!server_key) {
            std::cerr << "Failed to generate server key.\n";
            X509_free(ca_cert);
            EVP_PKEY_free(ca_key);
            return 1;
        }
        std::cout << "✓ Server Private Key generated successfully\n";
        std::cout << "Server Private Key:\n" << serialize_key(server_key) << "\n";

        // Tạo server certificate
        X509* server_cert = generate_cert("AuthServer", "CA", ca_key, server_key);
        if (!server_cert) {
            std::cerr << "Failed to generate server certificate.\n";
            EVP_PKEY_free(server_key);
            X509_free(ca_cert);
            EVP_PKEY_free(ca_key);
            return 1;
        }
        std::cout << "✓ Server Certificate generated successfully\n";
        std::cout << "Server Certificate:\n" << serialize_cert(server_cert) << "\n";

        std::cout << "\n=== STEP 3: GENERATING PEER CREDENTIALS ===\n";

        // Tạo peer key
        EVP_PKEY* peer_key = generate_key();
        if (!peer_key) {
            std::cerr << "Failed to generate peer key.\n";
            X509_free(server_cert);
            EVP_PKEY_free(server_key);
            X509_free(ca_cert);
            EVP_PKEY_free(ca_key);
            return 1;
        }
        std::cout << "✓ Peer Private Key generated successfully\n";
        std::cout << "Peer Private Key:\n" << serialize_key(peer_key) << "\n";

        // Tạo peer certificate
        X509* peer_cert = generate_cert("Peer", "CA", ca_key, peer_key);
        if (!peer_cert) {
            std::cerr << "Failed to generate peer certificate.\n";
            EVP_PKEY_free(peer_key);
            X509_free(server_cert);
            EVP_PKEY_free(server_key);
            X509_free(ca_cert);
            EVP_PKEY_free(ca_key);
            return 1;
        }
        std::cout << "✓ Peer Certificate generated successfully\n";
        std::cout << "Peer Certificate:\n" << serialize_cert(peer_cert) << "\n";

        std::cout << "\n=== STEP 4: CREATING EAP COMPONENTS ===\n";

        // Tạo các thành phần
        auto auth_server = std::make_unique<AuthenticationServer>("AuthServer", server_cert, server_key, ca_cert);
        std::cout << "✓ Authentication Server created\n";

        auto authenticator = std::make_unique<EAPAuthenticator>(auth_server.get());
        std::cout << "✓ EAP Authenticator created\n";

        auto peer = std::make_unique<EAPPeer>("Peer", peer_cert, peer_key, ca_cert);
        std::cout << "✓ EAP Peer created\n";

        std::cout << "\n=== STEP 5: STARTING EAP-TLS AUTHENTICATION PROCESS ===\n";
        std::cout << "Initiating EAP-TLS handshake...\n";
        std::cout << "==========================================\n";

        // Bắt đầu quá trình xác thực
        peer->start(authenticator.get());

        std::cout << "==========================================\n";
        std::cout << "✓ EAP-TLS Authentication Process Completed\n";

        // Giải phóng bộ nhớ
        X509_free(ca_cert);
        X509_free(server_cert);
        X509_free(peer_cert);
        EVP_PKEY_free(ca_key);
        EVP_PKEY_free(server_key);
        EVP_PKEY_free(peer_key);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}