#pragma once
#include <vector>
#include <cstdint>
#include <string>


#define PAYLOAD_NONE        0   // No next payload
#define PAYLOAD_SA          33  // Security Association
#define PAYLOAD_KE          34  // Key Exchange
#define PAYLOAD_IDI         35  // Identification - Initiator
#define PAYLOAD_IDR         36  // Identification - Responder
#define PAYLOAD_AUTH        39  // Authentication
#define PAYLOAD_CERT        37  // Certificate
#define PAYLOAD_CERTREQ     38  // Certificate Request
#define PAYLOAD_NONCE       40  // Nonce (Ni/Nr)
#define PAYLOAD_NOTIFY      41  // Notify
#define PAYLOAD_DELETE      42  // Delete
#define PAYLOAD_VENDOR_ID   43  // Vendor ID
#define PAYLOAD_TSi         44  // Traffic Selector - Initiator
#define PAYLOAD_TSr         45  // Traffic Selector - Responder
#define PAYLOAD_CP          46  // Configuration Payload
#define PAYLOAD_EAP         47  // Extensible Authentication Protocol (EAP)

#define PAYLOAD_HEADER_SIZE 4
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
IKEPayload buildKEPayload(const std::string& publicKeyHex);
IKEPayload parseKEPayload(const std::vector<uint8_t>& data); 

// Nonce (Ni/Nr) Payload
IKEPayload buildNoncePayload(const std::string& nonceHex);
IKEPayload parseNoncePayload(const std::vector<uint8_t>& data); 

std::vector<uint8_t> hexToBinary(const std::string& hex); 
std::string binaryToHex(const std::vector<uint8_t>& binary); 