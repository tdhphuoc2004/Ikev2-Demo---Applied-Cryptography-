#include "InitiatorIKEHeader.h"
#include "InitiatorIKEMessage.h"
#include "InitiatorCertificate.h"
#include "InitiatorIKEPayload.h"

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

std::vector<uint8_t> hexToBinary(const std::string& hex) {
    // Allocate vector with correct size (hex string length / 2)
    std::vector<uint8_t> binary(hex.size() / 2);

    try {
        CryptoPP::StringSource(hex, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::ArraySink(binary.data(), binary.size())
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        // Handle invalid hex string
        throw std::runtime_error("Invalid hex string: " + std::string(e.what()));
    }

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
IKEPayload buildKEPayload(const std::string& publicKeyHex, PayloadType nextType) {
    IKEPayload ke;
    ke.nextPayload = static_cast<uint8_t> (nextType); // Nonce follows KE
    // Convert hex public key to binary using Crypto++
    ke.data = hexToBinary(publicKeyHex);
    ke.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + ke.data.size());
    std::cout << "KE payload:" << ke.payloadLength << std::endl;
    return ke;
}

// Parse Key Exchange (KE) Payload
IKEPayload parseKEPayload(const std::vector<uint8_t>& data) {
    IKEPayload ke;
    ke.data = data;

    std::string publicKeyHex = binaryToHex(ke.data);
    std::cout << "Parsed KE public key: " << publicKeyHex << std::endl;

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
    std::cout << "Nonce payload:" << nonce.payloadLength << std::endl;
    return nonce;
}

// Parse Nonce (Ni/Nr) Payload
IKEPayload parseNoncePayload(const std::vector<uint8_t>& data) {
    IKEPayload nonce;
    nonce.data = data;

    std::string nonceHex = binaryToHex(nonce.data);
    std::cout << "Parsed Nonce: " << nonceHex << std::endl;

    nonce.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + nonce.data.size());
    return nonce;
}

// Build CAREQ payload 
IKEPayload buildCAREQPayload(X509* certificate, PayloadType nextType)
{
    IKEPayload careq;
    careq.nextPayload = static_cast<uint8_t> (nextType);
    careq.payloadLength = 0;

    // Check if certificate is valid
    if (!certificate) {
        fprintf(stderr, "Error: Invalid certificate\n");
        return careq;
    }

    // Get the certificate's subject name
    X509_NAME* subject = X509_get_subject_name(certificate);
    if (!subject) {
        fprintf(stderr, "Failed to get certificate subject\n");
        return careq;
    }

    // Convert subject to DER format
    unsigned char* der_data = nullptr;
    int der_length = i2d_X509_NAME(subject, &der_data);
    if (der_length < 0 || !der_data) {
        fprintf(stderr, "Failed to convert subject to DER format\n");
        return careq;
    }

    // Create CAREQ data field 
    // Certificate Encoding Type (X.509 Certificate - Signature)
    std::vector<uint8_t> payload;
    payload.reserve(1 + der_length);
    payload.push_back(X509Cert_Signature);

    // Add the DER-encoded subject name
    payload.insert(payload.end(), der_data, der_data + der_length);

    // Free the DER data
    OPENSSL_free(der_data);

    // Set the payload data
    careq.data = std::move(payload);
    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + careq.data.size());

    return careq;
}

IKEPayload parseCAREQPayload(const std::vector<uint8_t>& data)
{
    IKEPayload careq;
    careq.nextPayload = static_cast<uint8_t>(PayloadType::NONE);
    careq.payloadLength = 0;

    // Check minimum payload size (at least certificate type byte)
    if (data.size() < 1) {
        fprintf(stderr, "Error: CAREQ payload too short\n");
        return careq;
    }

    // Get certificate encoding type
    uint8_t certType = data[0];
    if (certType != X509Cert_Signature) {
        fprintf(stderr, "Error: Unsupported certificate type: %d\n", certType);
        return careq;
    }

    // Get the DER-encoded subject name (rest of payload after cert type)
    std::vector<uint8_t> derData(data.begin() + 1, data.end());


    // Store complete payload data
    careq.data = data;
    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + data.size());

    return careq;
}