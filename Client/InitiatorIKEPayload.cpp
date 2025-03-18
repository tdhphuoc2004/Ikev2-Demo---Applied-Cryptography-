#include "InitiatorIKEHeader.h"
#include "InitiatorIKEMessage.h"
#include "InitiatorIKEPayload.h"
#include "InitiatorCrypto.h"

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

IKEPayload buildEncryptedPayload(const std::vector<uint8_t>& plaintext, const std::string& aesKeyHex, PayloadType nextType)
{
    IKEPayload encPayload;
    encPayload.nextPayload = static_cast<uint8_t>(nextType);

    // Generate a random IV
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    InitiatorCrypto::GenerateIV(iv);
    // Print IV as hex (byte by byte)
    printf("IV: ");
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i) {
        printf("%02x ", iv[i]);  // Print each byte as 2-digit hex
    }
    printf("\n");
    
    std::string plainStr(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    std::string cipherStr = InitiatorCrypto::EncryptAES_CBC(plainStr, aesKeyHex, iv);

    // Format the payload data as [IV || ciphertext]
    encPayload.data.insert(encPayload.data.end(), iv, iv + CryptoPP::AES::BLOCKSIZE);
    encPayload.data.insert(encPayload.data.end(), cipherStr.begin(), cipherStr.end());

    encPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + encPayload.data.size());
    return encPayload;
}

std::vector<uint8_t> parseEncryptedPayload(const IKEPayload& encPayload, const std::string& aesKeyHex)
{
    return std::vector<uint8_t>();
}


IKEPayload buildAuthPayload(const std::vector<uint8_t>& signature, PayloadType nextType) 
{
    IKEPayload authPayload;
    authPayload.nextPayload = static_cast<uint8_t>(nextType);

    authPayload.data = signature;
    authPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + authPayload.data.size());

    return authPayload;
}


IKEPayload buildIDPayload(const std::string& identity, PayloadType nextType)
{
    IKEPayload idPayload;
    idPayload.nextPayload = static_cast<uint8_t>(nextType);

    // Append the identity data 
    idPayload.data.insert(idPayload.data.end(), identity.begin(), identity.end());

    idPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + idPayload.data.size());
    return idPayload;
}
