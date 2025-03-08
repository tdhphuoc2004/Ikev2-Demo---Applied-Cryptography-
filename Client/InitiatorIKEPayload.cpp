#include "InitiatorIKEHeader.h"
#include "InitiatorIKEMessage.h"
#include "InitiatorCertificate.h"
#include "InitiatorIKEPayload.h"
#include "SAPayload.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cryptlib.h>
#include <hex.h>
#include <filters.h>

#include <vector>
#include <string>
#include <cstring>

using namespace CryptoPP;

// Convert Generic Payload to Binary
std::vector<uint8_t> IKEPayload::toByteArray() {
    std::vector<uint8_t> buffer(PAYLOAD_HEADER_SIZE + data.size(), 0);

    buffer[0] = nextPayload;
    buffer[1] = critical;
    std::memcpy(&buffer[2], &payloadLength, sizeof(uint16_t));
    std::memcpy(&buffer[PAYLOAD_HEADER_SIZE], data.data(), data.size());

    return buffer;
}

std::vector<uint8_t> hexToBinary(const std::string& hex) 
{
    std::vector<uint8_t> binary(hex.size() / 2);
    CryptoPP::StringSource(hex, true,
        new CryptoPP::HexDecoder
        (
            new CryptoPP::ArraySink(binary.data(), binary.size())
        )
    );
    return binary;
}

std::string binaryToHex(const std::vector<uint8_t>& binary) 
{
    std::string hex;

    CryptoPP::StringSource(
        binary.data(),
        binary.size(),
        true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(hex)
        )
    );

    return hex;
}

// Build Key Exchange (KE) Payload
IKEPayload buildKEPayload(const std::string& publicKeyHex, PayloadType nextType) 
{
    IKEPayload ke;
    ke.nextPayload = static_cast<uint8_t> (nextType); // Nonce follows KE
    // Convert hex public key to binary using Crypto++
    ke.data = hexToBinary(publicKeyHex);
    ke.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + ke.data.size());
    return ke;
}

// Parse Key Exchange (KE) Payload
IKEPayload parseKEPayload(const std::vector<uint8_t>& data) 
{
    IKEPayload ke;
    ke.data = data;
    std::string publicKeyHex = binaryToHex(ke.data);
    ke.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + ke.data.size());
    return ke;
}


// Build Nonce (Ni/Nr) Payload
IKEPayload buildNoncePayload(const std::string& nonceHex, PayloadType nextType) {
    IKEPayload nonce;
    nonce.nextPayload = static_cast<uint8_t> (nextType);
    // Convert hex nonce to binary using Crypto++
    nonce.data = hexToBinary(nonceHex);
    nonce.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + nonce.data.size());
    return nonce;
}

// Parse Nonce (Ni/Nr) Payload
IKEPayload parseNoncePayload(const std::vector<uint8_t>& data) 
{
    IKEPayload nonce;
    nonce.data = data;
    std::string nonceHex = binaryToHex(nonce.data);
    nonce.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + nonce.data.size());
    return nonce;
}

// Build CAREQ payload 
IKEPayload buildCAREQPayload(const std::string& caName, PayloadType nextType)
{
    IKEPayload careq;
    careq.nextPayload = static_cast<uint8_t>(nextType);
    careq.payloadLength = 0;

    // Create payload vector
    std::vector<uint8_t> payload;

    // Add certificate type (X.509 Certificate - Signature)
    payload.push_back(X509Cert_Signature);

    // Hash the CA name using SHA-256
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx) {
        std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
        unsigned int hashLen;

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) &&
            EVP_DigestUpdate(mdctx, caName.c_str(), caName.length()) &&
            EVP_DigestFinal_ex(mdctx, hash.data(), &hashLen)) 
        {
            // Add hash to payload
            hash.resize(hashLen);
            payload.insert(payload.end(), hash.begin(), hash.end());
        }
        EVP_MD_CTX_free(mdctx);
    }

    // Set the payload data
    careq.data = std::move(payload);
    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + careq.data.size());

    fprintf(stdout, "Built CERTREQ payload for CA: %s\n", caName.c_str());
    return careq;
}

// Parse CAREQ payload
IKEPayload parseCAREQPayload(const std::vector<uint8_t>& data)
{
    IKEPayload careq;
    careq.nextPayload = static_cast<uint8_t>(PayloadType::NONE);
    careq.payloadLength = 0;

    // Check minimum payload size (cert type + at least some hash data)
    if (data.size() < (1 + SHA256_DIGEST_LENGTH)) 
    {
        fprintf(stderr, "Error: CAREQ payload too short\n");
        return careq;
    }

    // Get certificate encoding type
    uint8_t certType = data[0];
    if (certType != X509Cert_Signature) 
    {
        fprintf(stderr, "Error: Unsupported certificate type: %d\n", certType);
        return careq;
    }

    // Extract CA hash (rest of payload after cert type)
    std::vector<uint8_t> caHash(data.begin() + 1, data.end());

    // Convert hash to hex string for display
    std::string hashHex;
    for (const auto& byte : caHash) 
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        hashHex += hex;
    }
    // Store complete payload data
    careq.data = data;
    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + data.size());
    return careq;
}
