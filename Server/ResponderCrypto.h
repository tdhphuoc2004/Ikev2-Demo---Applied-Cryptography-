#pragma once
#include <string>
#include <cryptlib.h>
#include <secblock.h>

class ResponderCrypto {
public:
    // Generate Diffie-Hellman Key Pair (KEi)
    static void generateDHKey(std::string& publicKey);

    // Generate Nonce (Ni)
    static void generateNonce(std::string& nonce);

    // Calculating Shared Secret Key DH 
    static void calculateSharedSecret(const std::string& initiatorPublicKeyHex, const std::string & responderPrivateKey, std::string& sharedSecretHex); 

    // Encrypt message (AES-GCM)
   // static std::string encryptMessage(const std::string& plaintext, const std::string& key, const std::string& iv);

    // Decrypt message (AES-GCM)
   // static std::string decryptMessage(const std::string& ciphertext, const std::string& key, const std::string& iv);

    // Compute HMAC for Integrity Check
  //  static std::string computeHMAC(const std::string& message, const std::string& key);
};