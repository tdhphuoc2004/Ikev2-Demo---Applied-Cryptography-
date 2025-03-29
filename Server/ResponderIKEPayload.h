#pragma once
#include <vector>
#include <cstdint>
#include <string>

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
    ENCR = 46 // Encrypt payload 
};

enum class IdentificationType : uint8_t
{
    NONE = 0,
    ID_IPV4_ADDR = 1,
    ID_FQDN = 2,
    ID_RFC822_ADDR = 3,
    ID_IPV6_ADDR = 5,
    ID_DER_ASN1_DN = 9,
    ID_DER_ASN1_GN = 10,
    ID_KEY_ID = 11
};

constexpr uint16_t PAYLOAD_HEADER_SIZE = 4;
constexpr uint16_t ID_TRUELY_DATA_SIZE = 4;


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

//Encrypted Payload
IKEPayload buildEncryptedPayload(const std::vector<uint8_t>& plaintext, const std::string& aesKeyHex, PayloadType nextType);
std::vector<uint8_t> parseEncryptedPayload(const IKEPayload& encPayload, const std::string& aesKeyHex);

// Identification Payload 
IKEPayload buildIDPayload(const std::string& identity, PayloadType nextType);
IKEPayload parseIDPayload(const std::vector<uint8_t>& data);

// Authentication Payload
IKEPayload buildAuthPayload(const std::vector<uint8_t>& signature, PayloadType nextType); 
IKEPayload parseAuthPayload(const std::vector<uint8_t>& data);

std::vector<uint8_t> hexToBinary(const std::string& hex);
std::string binaryToHex(const std::vector<uint8_t>& binary);