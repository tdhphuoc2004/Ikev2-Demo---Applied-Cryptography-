#pragma once
#include <cstdint>
#include <vector>

// Proposal Protocol 
enum class ProtocolID : uint8_t
{
    IKE = 1,
    AH = 2,
    ESP = 3
};
// Transform Type IDs
enum class TransformType : uint8_t {
    ENCR = 1,   // Encryption Algorithm
    PRF = 2,    // Pseudorandom Function
    INTEG = 3,  // Integrity Algorithm
    DH = 4      // Diffie-Hellman Group
};

// Encryption Algorithms (Transform ID for ENCR)
enum class EncryptionAlgorithm : uint16_t {
    AES_CBC_128 = 12,
    AES_CBC_256 = 13,
    AES_GCM_128 = 20,
    AES_GCM_256 = 21
};

// Pseudorandom Function (Transform ID for PRF)
enum class PRFAlgorithm : uint16_t {
    HMAC_SHA256 = 5,
    HMAC_SHA384 = 6
};

// Integrity Algorithms (Transform ID for INTEG)
enum class IntegrityAlgorithm : uint16_t {
    HMAC_SHA256_128 = 12,
    HMAC_SHA384_192 = 14,
    AES_GMAC_128 = 22,
    AES_GMAC_256 = 23
};

// Diffie-Hellman Groups (Transform ID for DH)
enum class DHGroup : uint16_t {
    ECP_256 = 19,
    ECP_384 = 20
};

// Transform Structure (Each Proposal contains multiple transforms)
struct Transform {
    TransformType type;   // Transform Type (ENCR, PRF, INTEG, DH)
    uint16_t transformID; // Specific Algorithm ID (e.g., AES-CBC-128 = 12)
};

// Proposal Structure (Each SA Payload contains at least one Proposal)
struct Proposal {
    uint8_t proposalNumber;  // Proposal ID
    uint8_t protocolID;      // Protocol (1 = IKE, 2 = AH, 3 = ESP)
    uint8_t spiSize;         // SPI Size (0 for IKE SA, 4 or 8 for ESP)
    uint16_t length;         // Total length of proposal
    std::vector<Transform> transforms; // List of cryptographic transforms
};

// SA Payload Structure
struct SAPayload {
    uint8_t nextPayload;     // Next payload type
    uint8_t critical = 0;    // Must be zero
    uint16_t payloadLength;  // Total length of SA Payload
    std::vector<Proposal> proposals; // List of proposals
};
