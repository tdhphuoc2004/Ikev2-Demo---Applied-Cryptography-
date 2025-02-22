#pragma once
#include <vector>
#include <cstdint>
#include <string>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

enum class PayloadType : uint8_t {
    NONE = 0,    // No next payload
    SA = 33,   // Security Association
    KE = 34,   // Key Exchange
    IDI = 35,   // Identification - Initiator
    IDR = 36,   // Identification - Responder
    CERT = 37,   // Certificate
    CERTREQ = 38,   // Certificate Request
    AUTH = 39,   // Authentication
    NONCE = 40,   // Nonce (Ni/Nr)
    NOTIFY = 41,   // Notify
    //DELETE = 42,   // Delete
    VENDOR_ID = 43,   // Vendor ID
    TSi = 44,   // Traffic Selector - Initiator
    TSr = 45,   // Traffic Selector - Responder
    CP = 46,   // Configuration Payload
    EAP = 47    // Extensible Authentication Protocol (EAP)
};

constexpr uint16_t PAYLOAD_HEADER_SIZE = 4;


// Generic IKE Payload Structure
struct IKEPayload {
    uint8_t nextPayload;
    uint8_t critical = 0;
    // No need to create Reserved field, this is so complicated 
    uint16_t payloadLength;
    std::vector<uint8_t> data;

    std::vector<uint8_t> toByteArray();
};


// KE Payload
IKEPayload buildKEPayload(const std::string& publicKeyHex, PayloadType nextType);
IKEPayload parseKEPayload(const std::vector<uint8_t>& data);

// Nonce (Ni/Nr) Payload
IKEPayload buildNoncePayload(const std::string& nonceHex, PayloadType nextType);
IKEPayload parseNoncePayload(const std::vector<uint8_t>& data);

// CAREQ Payload 
IKEPayload buildCAREQPayload(const std::string& caName, PayloadType nextType); 
IKEPayload parseCAREQPayload(const std::vector<uint8_t>& data); 

std::vector<uint8_t> hexToBinary(const std::string& hex);
std::string binaryToHex(const std::vector<uint8_t>& binary);