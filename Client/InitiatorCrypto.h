#pragma once
#include <string>
#include <cryptlib.h>
#include <secblock.h>
#include <iostream>
class InitiatorCrypto {
public:
    // Generating Diffie-Hellman Key Pair (KEi)
    static void generateDHKey(std::string& privateKeyHex, std::string& publicKeyHex); 

    // Generating Nonce (Ni)
    static void generateNonce(std::string& nonce);

    // Computing shared secret DH key 
    static void calculateSharedSecret(const std::string& responderPublicKeyHex, const std::string& initiatorPrivateKeyHex, std::string& sharedSecretHex); 

    // Computing key in pseudorandom and deriving it to many keys 
    static std::string generateSKEYSEED(const std::string& sharedSecret, const std::string& nonceI, const std::string& nonceR); 
    static std::string deriveKey(const std::string& key, const std::string& label, const std::string& data); 
    static void deriveKeys(const std::string& skeyseed, const std::string& nonceI, const std::string& nonceR, const uint64_t spiI, const uint64_t spiR, std::string& sk_d, std::string& sk_ai,
        std::string& sk_ar, std::string& sk_ei, std::string& sk_er); 

    // Encrypt message (AES-GCM)
   // static std::string encryptMessage(const std::string& plaintext, const std::string& key, const std::string& iv);

    // Decrypt message (AES-GCM)
   // static std::string decryptMessage(const std::string& ciphertext, const std::string& key, const std::string& iv);

    // Compute HMAC for Integrity Check
  //  static std::string computeHMAC(const std::string& message, const std::string& key);
};