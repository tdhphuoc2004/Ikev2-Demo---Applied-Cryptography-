#include "InitiatorCrypto.h"
#include <cryptlib.h>
#include <dh.h>
#include <osrng.h>
#include <hex.h>
#include <string>
#include <eccrypto.h>
#include <oids.h>


void InitiatorCrypto::generateDHKey(std::string& privateKeyHex, std::string& publicKeyHex)
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

    // Convert public key to hex 
    publicKeyHex.clear();
    CryptoPP::HexEncoder pubEncoder(new CryptoPP::StringSink(publicKeyHex));
    pubEncoder.Put(pubKey, pubKey.size());
    pubEncoder.MessageEnd();
}

void InitiatorCrypto::generateNonce(std::string& nonce) {
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

void InitiatorCrypto::calculateSharedSecret(
    const std::string& responderPublicKeyHex,
    const std::string& initiatorPrivateKeyHex,
    std::string& sharedSecretHex
)
{
    if (responderPublicKeyHex.empty() || initiatorPrivateKeyHex.empty()) {
        throw std::invalid_argument("Empty public/private key input");
    }

    // Initialize ECDH parameters for secp256r1 (NIST P-256, Group 19)
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1());
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);

    // Convert initiator's public key from hex to SecByteBlock
    CryptoPP::SecByteBlock initiatorPublicKey = hexToSecByteBlock(responderPublicKeyHex);

    // Convert responder's private key from hex to SecByteBlock
    CryptoPP::SecByteBlock responderPrivateKey = hexToSecByteBlock(initiatorPrivateKeyHex);


    // Compute shared secret
    CryptoPP::SecByteBlock sharedSecret(dhDomain.AgreedValueLength());
    if (!dhDomain.Agree(sharedSecret, responderPrivateKey, initiatorPublicKey)) {
        throw std::runtime_error("ECDH key agreement failed");
    }

    // Convert shared secret to hex
    sharedSecretHex = secByteBlockToHex(sharedSecret);
}


// Function to generate SKEYSEED using HMAC-SHA256
std::string InitiatorCrypto::generateSKEYSEED(const std::string& sharedSecret, const std::string& nonceI, const std::string& nonceR) 
{
    // Convert hex inputs to binary
    CryptoPP::SecByteBlock secret = hexToSecByteBlock(sharedSecret);
    CryptoPP::SecByteBlock ni = hexToSecByteBlock(nonceI);
    CryptoPP::SecByteBlock nr = hexToSecByteBlock(nonceR);

    // Concatenate nonces (Ni | Nr)
    CryptoPP::SecByteBlock nonceData(ni.size() + nr.size());
    memcpy(nonceData, ni.data(), ni.size());
    memcpy(nonceData + ni.size(), nr.data(), nr.size());

    // Prepare output buffer for SKEYSEED
    CryptoPP::SecByteBlock skeyseed(CryptoPP::SHA256::DIGESTSIZE);

    // Calculate HMAC-SHA256
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(secret, secret.size());
    hmac.CalculateDigest(skeyseed, nonceData, nonceData.size());

    // Convert result to hex
    std::string result;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
    encoder.Put(skeyseed, skeyseed.size());
    encoder.MessageEnd();

    return result;
}

std::string InitiatorCrypto::deriveKey(const std::string& key, const std::string& label, const std::string& baseString)
{
    CryptoPP::SecByteBlock keyBytes = hexToSecByteBlock(key);
    std::string derivationData = label + baseString;

    CryptoPP::SecByteBlock derivedKey(CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(keyBytes, keyBytes.size());
    hmac.CalculateDigest(derivedKey,
        reinterpret_cast<const CryptoPP::byte*>(derivationData.data()),
        derivationData.size());

    std::string result;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
    encoder.Put(derivedKey, derivedKey.size());
    encoder.MessageEnd();

    return result;
}

void InitiatorCrypto::deriveKeys
(
    const std::string& skeyseed,
    const std::string& nonceI,
    const std::string& nonceR,
    const uint64_t spiI,
    const uint64_t spiR,
    std::string& sk_d,
    std::string& sk_ai,
    std::string& sk_ar,
    std::string& sk_ei,
    std::string& sk_er
)
{
    // Create base string for key derivation
    std::stringstream ss;
    ss << nonceI << nonceR << std::hex << spiI << spiR;
    std::string baseString = ss.str();

    // Derive all keys
    sk_d = deriveKey(skeyseed, "\x00", baseString);
    sk_ai = deriveKey(sk_d, "\x01", baseString);
    sk_ar = deriveKey(sk_d, "\x02", baseString);
    sk_ei = deriveKey(sk_d, "\x03", baseString);
    sk_er = deriveKey(sk_d, "\x04", baseString);
}


//std::string InitiatorCrypto::encryptMessage(const std::string& plaintext, const std::string& key, const std::string& iv) {
//    CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
//    encryption.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data(), iv.size());
//
//    std::string ciphertext;
//    CryptoPP::StringSource ss(plaintext, true,
//        new CryptoPP::AuthenticatedEncryptionFilter(encryption,
//            new CryptoPP::StringSink(ciphertext)
//        )
//    );
//    return ciphertext;
//}
//
//std::string InitiatorCrypto::decryptMessage(const std::string& ciphertext, const std::string& key, const std::string& iv) {
//    CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
//    decryption.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data(), iv.size());
//
//    std::string decrypted;
//    CryptoPP::StringSource ss(ciphertext, true,
//        new CryptoPP::AuthenticatedDecryptionFilter(decryption,
//            new CryptoPP::StringSink(decrypted)
//        )
//    );
//    return decrypted;
//}
//
//std::string InitiatorCrypto::computeHMAC(const std::string& message, const std::string& key) {
//    CryptoPP::HMAC<CryptoPP::SHA256> hmac((byte*)key.data(), key.size());
//
//    std::string mac;
//    CryptoPP::StringSource ss(message, true,
//        new CryptoPP::HashFilter(hmac,
//            new CryptoPP::HexEncoder(new CryptoPP::StringSink(mac))
//        )
//    );
//    return mac;
//}
