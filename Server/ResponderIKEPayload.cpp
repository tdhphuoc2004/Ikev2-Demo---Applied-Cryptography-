#include "ResponderIKEHeader.h"
#include "ResponderIKEMessage.h"

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
IKEPayload buildKEPayload(const std::string& publicKeyHex) {
    IKEPayload ke;
    ke.nextPayload = PAYLOAD_NONCE; // Nonce follows KE
    // Convert hex public key to binary using Crypto++
    ke.data = hexToBinary(publicKeyHex);
    ke.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + ke.data.size());
    std::cout << "KE payload:" << ke.payloadLength << std::endl;
    return ke;
}

// Build Nonce (Ni/Nr) Payload
IKEPayload buildNoncePayload(const std::string& nonceHex) {
    IKEPayload nonce;
    nonce.nextPayload = PAYLOAD_NONE;
    // Convert hex nonce to binary using Crypto++
    nonce.data = hexToBinary(nonceHex);
    nonce.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + nonce.data.size());
    std::cout << "Nonce payload:" << nonce.payloadLength << std::endl;
    return nonce;
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

// Parse Nonce (Ni/Nr) Payload
IKEPayload parseNoncePayload(const std::vector<uint8_t>& data) {
    IKEPayload nonce;
    nonce.data = data;

    std::string nonceHex = binaryToHex(nonce.data);
    std::cout << "Parsed Nonce: " << nonceHex << std::endl;

    nonce.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + nonce.data.size());
    return nonce;
}
