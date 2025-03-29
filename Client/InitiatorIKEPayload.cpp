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
    // Extract the IV (first AES_BLOCK_SIZE bytes from the payload)
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    std::copy(encPayload.data.begin(), encPayload.data.begin() + CryptoPP::AES::BLOCKSIZE, iv);

    // The rest is the ciphertext
    std::string ciphertext(encPayload.data.begin() + CryptoPP::AES::BLOCKSIZE, encPayload.data.end());

    // Decrypt the ciphertext using AES CBC mode
    std::string decryptedText = InitiatorCrypto::DecryptAES_CBC(ciphertext, aesKeyHex, iv);

    std::vector<uint8_t> decryptedData(decryptedText.begin(), decryptedText.end());

    return decryptedData;
}

IKEPayload buildAuthPayload(const std::vector<uint8_t>& signature, PayloadType nextType) 
{
    IKEPayload authPayload;
    authPayload.nextPayload = static_cast<uint8_t>(nextType);

    authPayload.data = signature;
    authPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + authPayload.data.size());

    return authPayload;
}

IKEPayload parseAuthPayload(const std::vector<uint8_t>& data)
{
    IKEPayload authPayload;
    authPayload.data = data;
    authPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + authPayload.data.size());
    return authPayload;
}


IKEPayload buildIDPayload(const std::string& identity, PayloadType nextType)
{
    IKEPayload idPayload;
    idPayload.nextPayload = static_cast<uint8_t>(nextType);

    // Append the identity data 
    IdentificationType idType = IdentificationType::ID_FQDN;
    uint8_t rawIDType = static_cast<uint8_t>(idType);
    idPayload.data.push_back(rawIDType);  // ID Type (1 byte)
    idPayload.data.push_back(0x00);    // Reserved byte 1
    idPayload.data.push_back(0x00);    // Reserved byte 2
    idPayload.data.push_back(0x00);    // Reserved byte 3
    idPayload.data.insert(idPayload.data.end(), identity.begin(), identity.end());

    idPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + idPayload.data.size());
    return idPayload;
}

IKEPayload parseIDPayload(const std::vector<uint8_t>& data)
{
    IKEPayload idPayload;
    idPayload.data = data;
    idPayload.payloadLength = static_cast<uint16_t>(PAYLOAD_HEADER_SIZE + idPayload.data.size());
    return idPayload;
}

