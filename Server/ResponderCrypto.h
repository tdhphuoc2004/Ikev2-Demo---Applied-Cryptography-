#pragma once
#include <string>
#include <cryptlib.h>
#include <secblock.h>
#include <aes.h>
#include <modes.h>

class ResponderCrypto {
public:
    static void generateDHKey(std::string& privateKeyHex, std::string& publicKeyHex);

    // Generating Nonce (Ni)
    static void generateNonce(std::string& nonce);

    // Calculating Shared Secret Key DH 
    static void calculateSharedSecret(const std::string& initiatorPublicKeyHex, const std::string & responderPrivateKey, std::string& sharedSecretHex); 

    // Computing key in pseudorandom and deriving it to many keys 
    static std::string generateSKEYSEED(const std::string& sharedSecret, const std::string& nonceI, const std::string& nonceR);
    static std::string prf(const std::string& keyHex, const std::string& data); 
    static std::string prfPlus(const std::string& keyHex, const std::string& seed, size_t desiredLen);
    static void deriveKeys(const std::string& skeyseedHex, const std::string& nonceI, const std::string& nonceR, uint64_t spiI, uint64_t spiR, std::string& sk_dHex, std::string& sk_aiHex, std::string& sk_arHex, std::string& sk_eiHex, std::string& sk_erHex);

    // Encryption AES-CBC256
    static std::string DecryptAES_CBC(const std::string& cipherText, const std::string& key, const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]); 
    static std::string EncryptAES_CBC(const std::string& cipherText, const std::string& key, const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]);
    static void GenerateIV(CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]);

};

