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
// Build SA Payload

// Function to encode a single Proposal 
//std::vector<uint8_t> encodeProposal(const Proposal& proposal, bool isLast) 
//{
//    std::vector<uint8_t> proposalData;
//
//    // First byte: Last Substruc (2 if last proposal, 0 otherwise)
//    proposalData.push_back(isLast ? 2 : 0);
//
//    // Placeholder for Proposal Length (2 bytes)
//    proposalData.push_back(0x00);
//    proposalData.push_back(0x00);
//
//    // Proposal fields
//    proposalData.push_back(proposal.proposalNumber);
//    proposalData.push_back(proposal.protocolID);
//    proposalData.push_back(proposal.transforms.size()); // Number of transforms
//
//    // Encode Transforms
//    for (const auto& transform : proposal.transforms) 
//    {
//        proposalData.push_back(static_cast<uint8_t>(transform.type)); // Transform Type
//        proposalData.push_back((transform.transformID >> 8) & 0xFF);
//        proposalData.push_back(transform.transformID & 0xFF);
//    }
//
//    // Update Proposal Length
//    uint16_t proposalLength = proposalData.size();
//    proposalData[2] = (proposalLength >> 8) & 0xFF;
//    proposalData[3] = proposalLength & 0xFF;
//
//    return proposalData;
//}


// Function to build SA Payload with multiple proposals
//IKEPayload buildSAPayload(const std::vector<Proposal>& proposals, PayloadType nextType) {
//    IKEPayload saPayload;
//    saPayload.nextPayload = static_cast<uint8_t>(nextType);
//
//    // Encode each proposal
//    for (size_t i = 0; i < proposals.size(); ++i) 
//    {
//        bool isLast = (i == proposals.size() - 1);
//        std::vector<uint8_t> proposalData = encodeProposal(proposals[i], isLast);
//        saPayload.data.insert(saPayload.data.end(), proposalData.begin(), proposalData.end());
//    }
//
//
//    // Compute SA Payload Length
//    saPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + saPayload.data.size());
//    std::cout << "SA Payload Length: " << saPayload.payloadLength << " bytes" << std::endl;
//
//    return saPayload;
//}
 
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
            EVP_DigestFinal_ex(mdctx, hash.data(), &hashLen)) {

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

IKEPayload parseCAREQPayload(const std::vector<uint8_t>& data)
{
    IKEPayload careq;
    careq.nextPayload = static_cast<uint8_t>(PayloadType::NONE);
    careq.payloadLength = 0;

    // Check minimum payload size (cert type + at least some hash data)
    if (data.size() < (1 + SHA256_DIGEST_LENGTH)) {
        fprintf(stderr, "Error: CAREQ payload too short\n");
        return careq;
    }

    // Get certificate encoding type
    uint8_t certType = data[0];
    if (certType != X509Cert_Signature) {
        fprintf(stderr, "Error: Unsupported certificate type: %d\n", certType);
        return careq;
    }

    // Extract CA hash (rest of payload after cert type)
    std::vector<uint8_t> caHash(data.begin() + 1, data.end());

    // Convert hash to hex string for display
    std::string hashHex;
    for (const auto& byte : caHash) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        hashHex += hex;
    }

    fprintf(stdout, "Parsed CERTREQ payload:\n");
    fprintf(stdout, "Certificate Type: X.509 Certificate - Signature\n");
    fprintf(stdout, "CA Hash: %s\n", hashHex.c_str());

    // Store complete payload data
    careq.data = data;
    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + data.size());

    return careq;
}

//IKEPayload buildCAREQPayload(X509* certificate, PayloadType nextType)
//{
//    IKEPayload careq;
//    careq.nextPayload = static_cast<uint8_t> (nextType);
//    careq.payloadLength = 0;
//
//    // Check if certificate is valid
//    if (!certificate) {
//        fprintf(stderr, "Error: Invalid certificate\n");
//        return careq;
//    }
//
//    // Get the certificate's subject name
//    X509_NAME* subject = X509_get_subject_name(certificate);
//    if (!subject) {
//        fprintf(stderr, "Failed to get certificate subject\n");
//        return careq;
//    }
//
//    // Convert subject to DER format
//    unsigned char* der_data = nullptr;
//    int der_length = i2d_X509_NAME(subject, &der_data);
//    if (der_length < 0 || !der_data) {
//        fprintf(stderr, "Failed to convert subject to DER format\n");
//        return careq;
//    }
//
//    // Create CAREQ data field 
//    // Certificate Encoding Type (X.509 Certificate - Signature)
//    std::vector<uint8_t> payload;
//    payload.reserve(1 + der_length);
//    payload.push_back(X509Cert_Signature);
//
//    // Add the DER-encoded subject name
//    payload.insert(payload.end(), der_data, der_data + der_length);
//
//    // Free the DER data
//    OPENSSL_free(der_data);
//
//    // Set the payload data
//    careq.data = std::move(payload);
//    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + careq.data.size());
//
//    return careq;
//}

//IKEPayload parseCAREQPayload(const std::vector<uint8_t>& data)
//{
//    IKEPayload careq;
//    careq.nextPayload = static_cast<uint8_t>(PayloadType::NONE);
//    careq.payloadLength = 0;
//
//    // Check minimum payload size (at least certificate type byte)
//    if (data.size() < 1) {
//        fprintf(stderr, "Error: CAREQ payload too short\n");
//        return careq;
//    }
//
//    // Get certificate encoding type
//    uint8_t certType = data[0];
//    if (certType != X509Cert_Signature) {
//        fprintf(stderr, "Error: Unsupported certificate type: %d\n", certType);
//        return careq;
//    }
//
//    // Get the DER-encoded subject name (rest of payload after cert type)
//    std::vector<uint8_t> derData(data.begin() + 1, data.end());
//
//
//    // Store complete payload data
//    careq.data = data;
//    careq.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + data.size());
//
//    return careq;
//}