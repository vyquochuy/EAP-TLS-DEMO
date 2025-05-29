#ifndef MESSAGES_H
#define MESSAGES_H

#include <string>

const std::string EAPOL_START = "EAPOL-Start";
const std::string EAP_REQUEST_IDENTITY = "EAP-Request/Identity";
const std::string EAP_RESPONSE_IDENTITY = "EAP-Response/Identity";
const std::string EAP_REQUEST_TLS_START = "EAP-Request/TLS-Start";
const std::string EAP_TLS_CLIENT_HELLO = "EAP-TLS-ClientHello";
const std::string EAP_TLS_SERVER_HELLO = "EAP-TLS-ServerHello";
const std::string EAP_TLS_PREMASTER_SECRET = "EAP-TLS-PreMasterSecret";
const std::string EAP_SUCCESS = "EAP-Success";
const std::string EAP_FAILURE = "EAP-Failure";

struct Message {
    std::string type;
    std::string data;
};

#endif // MESSAGES_H