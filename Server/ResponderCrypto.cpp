#include "ResponderCrypto.h"
#include <cryptlib.h>
#include <dh.h>
#include <osrng.h>
#include <hex.h>
#include <string>
#include <eccrypto.h>
#include <oids.h>


void ResponderCrypto::generateDHKey(std::string& privateKeyHex, std::string& publicKeyHex)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1());  // NIST P-256, SECP256R1

    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);

    // Generate keys 
    CryptoPP::SecByteBlock privateKey(dhDomain.PrivateKeyLength());
    CryptoPP::SecByteBlock pubKey(dhDomain.PublicKeyLength());
    dhDomain.GenerateKeyPair(rng, privateKey, pubKey);

    // Convert private key to hex
    privateKeyHex.clear();
    CryptoPP::HexEncoder privEncoder(new CryptoPP::StringSink(privateKeyHex));
    privEncoder.Put(privateKey, privateKey.size());
    privEncoder.MessageEnd();

    // Convert public key to hex (includes '04' prefix automatically)
    publicKeyHex.clear();
    CryptoPP::HexEncoder pubEncoder(new CryptoPP::StringSink(publicKeyHex));
    pubEncoder.Put(pubKey, pubKey.size());
    pubEncoder.MessageEnd();
}

void ResponderCrypto::generateNonce(std::string& nonce) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::byte randomBytes[16]; // 16-byte nonce
    rng.GenerateBlock(randomBytes, sizeof(randomBytes));

    // Convert to hex string
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(nonce));
    encoder.Put(randomBytes, sizeof(randomBytes));
    encoder.MessageEnd();
}



// Convert Hex-Encoded String to SecByteBlock
CryptoPP::SecByteBlock hexToSecByteBlock(const std::string& hexStr) 
{
    CryptoPP::SecByteBlock byteBlock(hexStr.size() / 2); // Each byte = 2 hex chars

    CryptoPP::StringSource(hexStr, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(byteBlock, byteBlock.size())
        )
    );

    return byteBlock;
}

// Convert SecByteBlock to Hex String
std::string secByteBlockToHex(const CryptoPP::SecByteBlock& byteBlock) {
    std::string hexStr;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexStr));
    encoder.Put(byteBlock, byteBlock.size());
    encoder.MessageEnd();

    return hexStr;
}


void ResponderCrypto::calculateSharedSecret(
    const std::string& initiatorPublicKeyHex,
    const std::string& responderPrivateKeyHex,
    std::string& sharedSecretHex
)
{
    if (initiatorPublicKeyHex.empty() || responderPrivateKeyHex.empty()) {
        throw std::invalid_argument("Empty public/private key input");
    }

    // Initialize ECDH parameters for secp256r1 (NIST P-256, Group 19)
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1());
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);

    // Convert initiator's public key from hex to SecByteBlock
    CryptoPP::SecByteBlock initiatorPublicKey = hexToSecByteBlock(initiatorPublicKeyHex);

    // Convert responder's private key from hex to SecByteBlock
    CryptoPP::SecByteBlock responderPrivateKey = hexToSecByteBlock(responderPrivateKeyHex);

  
    // Compute shared secret
    CryptoPP::SecByteBlock sharedSecret(dhDomain.AgreedValueLength());
    if (!dhDomain.Agree(sharedSecret, responderPrivateKey, initiatorPublicKey)) {
        throw std::runtime_error("ECDH key agreement failed");
    }

    // Convert shared secret to hex
    sharedSecretHex = secByteBlockToHex(sharedSecret);
}
