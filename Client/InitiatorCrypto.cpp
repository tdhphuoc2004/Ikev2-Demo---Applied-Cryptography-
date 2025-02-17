#include "InitiatorCrypto.h"
#include <cryptlib.h>
#include <dh.h>
#include <osrng.h>
#include <hex.h>
#include <string>
#include <eccrypto.h>
#include <oids.h>


void InitiatorCrypto::generateDHKey(std::string& publicKey) 
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1()); //  Group 19

    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);
    CryptoPP::SecByteBlock privateKey(dhDomain.PrivateKeyLength());
    CryptoPP::SecByteBlock pubKey(dhDomain.PublicKeyLength());

    dhDomain.GenerateKeyPair(rng, privateKey, pubKey);

    // Convert public key to hex
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(publicKey));
    encoder.Put(pubKey, pubKey.size());
    encoder.MessageEnd();

    // PublicKey of group 19 will have 65 bytes 
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

void InitiatorCrypto::calculateSharedSecret(
    const std::string& initiatorPublicKeyHex,
    const CryptoPP::SecByteBlock& responderPrivateKey,
    std::string& sharedSecretHex
)
{
    if (initiatorPublicKeyHex.empty() || responderPrivateKey.size() == 0) {
        throw std::invalid_argument("Empty public/private key input");
    }

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1());

    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);

    if (responderPrivateKey.size() != dhDomain.PrivateKeyLength()) {
        throw std::invalid_argument("Invalid responder private key size");
    }

    CryptoPP::SecByteBlock initiatorPublicKey(dhDomain.PublicKeyLength());
    CryptoPP::StringSource decoder(initiatorPublicKeyHex, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(initiatorPublicKey, initiatorPublicKey.size())
        )
    );

    CryptoPP::SecByteBlock sharedSecret(dhDomain.AgreedValueLength());
    if (!dhDomain.Agree(sharedSecret, responderPrivateKey, initiatorPublicKey)) {
        throw std::runtime_error("ECDH key agreement failed");
    }

    sharedSecretHex.clear();
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(sharedSecretHex));
    encoder.Put(sharedSecret, sharedSecret.size());
    encoder.MessageEnd();
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
