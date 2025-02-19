#pragma once
#include <string>
#include <cryptlib.h>
#include <secblock.h>

class InitiatorCrypto {
public:
    // Generate Diffie-Hellman Key Pair (KEi)
    static void generateDHKey(std::string& privateKeyHex, std::string& publicKeyHex); 

    // Generate Nonce (Ni)
    static void generateNonce(std::string& nonce);

    // Computing shared secret DH key 
    static void calculateSharedSecret(
        const std::string& responderPublicKeyHex,
        const std::string& initiatorPrivateKeyHex,
        std::string& sharedSecretHex
    );


    // Encrypt message (AES-GCM)
   // static std::string encryptMessage(const std::string& plaintext, const std::string& key, const std::string& iv);

    // Decrypt message (AES-GCM)
   // static std::string decryptMessage(const std::string& ciphertext, const std::string& key, const std::string& iv);

    // Compute HMAC for Integrity Check
  //  static std::string computeHMAC(const std::string& message, const std::string& key);
};