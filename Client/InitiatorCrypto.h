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
    static std::string prf(const std::string& keyHex, const std::string& data);
    static std::string prfPlus(const std::string& keyHex, const std::string& seed, size_t desiredLen); 
    static void deriveKeys(const std::string& skeyseedHex, const std::string& nonceI, const std::string& nonceR, uint64_t spiI, uint64_t spiR, std::string& sk_dHex, std::string& sk_aiHex, std::string& sk_arHex, std::string& sk_eiHex, std::string& sk_erHex);

};