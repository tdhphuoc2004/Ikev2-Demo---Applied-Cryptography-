#include <iostream>
#include <cryptlib.h>
#include <eccrypto.h>
#include <osrng.h>
#include <secblock.h>
#include <oids.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>

using namespace CryptoPP;

void TestECDH(const OID& curve, const std::string& groupName) {
    std::cout << "Testing ECDH with Group: " << groupName << std::endl;

    // Kh?i t?o b? t?o s? ng?u nhiên
    AutoSeededRandomPool rng;

    // Sinh private/public key cho Initiator
    ECDH<ECP>::Domain initiatorDomain(curve);
    SecByteBlock initiatorPrivateKey(initiatorDomain.PrivateKeyLength());
    SecByteBlock initiatorPublicKey(initiatorDomain.PublicKeyLength());
    initiatorDomain.GenerateKeyPair(rng, initiatorPrivateKey, initiatorPublicKey);

    // Sinh private/public key cho Responder
    ECDH<ECP>::Domain responderDomain(curve);
    SecByteBlock responderPrivateKey(responderDomain.PrivateKeyLength());
    SecByteBlock responderPublicKey(responderDomain.PublicKeyLength());
    responderDomain.GenerateKeyPair(rng, responderPrivateKey, responderPublicKey);

    // Trao ??i khóa và tính shared secret
    SecByteBlock initiatorSharedSecret(initiatorDomain.AgreedValueLength());
    SecByteBlock responderSharedSecret(responderDomain.AgreedValueLength());

    if (!initiatorDomain.Agree(initiatorSharedSecret, initiatorPrivateKey, responderPublicKey)) {
        std::cerr << "Error: Initiator failed to calculate shared secret!" << std::endl;
        return;
    }

    if (!responderDomain.Agree(responderSharedSecret, responderPrivateKey, initiatorPublicKey)) {
        std::cerr << "Error: Responder failed to calculate shared secret!" << std::endl;
        return;
    }

    // Ki?m tra shared secret t? hai phía
    if (initiatorSharedSecret == responderSharedSecret) {
        std::cout << "Shared secret successfully matched!" << std::endl;
    }
    else {
        std::cerr << "Error: Shared secret mismatch!" << std::endl;
        return;
    }

    // In shared secret (d?ng hex)
    std::cout << "Shared Secret (Hex): ";
    for (size_t i = 0; i < initiatorSharedSecret.size(); ++i) {
        std::cout << std::hex << (int)initiatorSharedSecret[i];
    }
    std::cout << std::endl;

    // S? d?ng shared secret làm khóa AES (c?t thành 16 byte n?u c?n)
    SecByteBlock aesKey(16);  // AES-128
    memcpy(aesKey, initiatorSharedSecret.data(), aesKey.size());

    // B?n rõ (Plaintext)
    std::string plaintext = "Hello, this is a test message!";
    std::cout << "Plaintext: " << plaintext << std::endl;

    // Mã hóa
    std::string encrypted;
    try {
        CBC_Mode<AES>::Encryption encryptor(aesKey, aesKey.size(), aesKey);  // IV = aesKey cho ??n gi?n
        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(encrypted)));
    }
    catch (const Exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return;
    }
    std::cout << "Encrypted (Hex): ";
    for (unsigned char c : encrypted) {
        std::cout << std::hex << (int)c;
    }
    std::cout << std::endl;

    // Gi?i mã
    std::string decrypted;
    try {
        CBC_Mode<AES>::Decryption decryptor(aesKey, aesKey.size(), aesKey);
        StringSource(encrypted, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decrypted)));
    }
    catch (const Exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        return;
    }
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << std::endl;
}

int main() {
    // Nhóm Diffie-Hellman (OID cho ???ng cong elliptic)
    TestECDH(ASN1::secp256r1(), "Group 19 (secp256r1)");
    TestECDH(ASN1::secp384r1(), "Group 20 (secp384r1)");

    return 0;
}
