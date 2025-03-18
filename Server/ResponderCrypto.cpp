#include "ResponderCrypto.h"
#include "Utils.h"

#include <cryptlib.h>
#include <dh.h>
#include <osrng.h>
#include <hex.h>
#include <string>
#include <eccrypto.h>
#include <oids.h>
#include <aes.h>
#include <modes.h>

void ResponderCrypto::generateDHKey(std::string& privateKeyHex, std::string& publicKeyHex)
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1());  // NIST P-256, SECP256R1

    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);

    // Generating keys 
    CryptoPP::SecByteBlock privateKey(dhDomain.PrivateKeyLength());
    CryptoPP::SecByteBlock pubKey(dhDomain.PublicKeyLength());
    dhDomain.GenerateKeyPair(rng, privateKey, pubKey);

    // Converting private key to hex
    privateKeyHex.clear();
    CryptoPP::HexEncoder privEncoder(new CryptoPP::StringSink(privateKeyHex));
    privEncoder.Put(privateKey, privateKey.size());
    privEncoder.MessageEnd();

    // Converting public key to hex 
    publicKeyHex.clear();
    CryptoPP::HexEncoder pubEncoder(new CryptoPP::StringSink(publicKeyHex));
    pubEncoder.Put(pubKey, pubKey.size());
    pubEncoder.MessageEnd();
}

void ResponderCrypto::generateNonce(std::string& nonce) 
{
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::byte randomBytes[16]; // 16-byte nonce
    rng.GenerateBlock(randomBytes, sizeof(randomBytes));

    // Converting to hex string
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(nonce));
    encoder.Put(randomBytes, sizeof(randomBytes));
    encoder.MessageEnd();
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

    // Initializing ECDH parameters for secp256r1 (NIST P-256, Group 19)
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> dhParams;
    dhParams.Initialize(CryptoPP::ASN1::secp256r1());
    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhDomain(dhParams);

    // Converting initiator's public key from hex to SecByteBlock
    CryptoPP::SecByteBlock initiatorPublicKey = hexToSecByteBlock(initiatorPublicKeyHex);

    // Converting responder's private key from hex to SecByteBlock
    CryptoPP::SecByteBlock responderPrivateKey = hexToSecByteBlock(responderPrivateKeyHex);

  
    // Computing shared secret
    CryptoPP::SecByteBlock sharedSecret(dhDomain.AgreedValueLength());
    if (!dhDomain.Agree(sharedSecret, responderPrivateKey, initiatorPublicKey)) {
        throw std::runtime_error("ECDH key agreement failed");
    }

    // Converting shared secret to hex
    sharedSecretHex = secByteBlockToHex(sharedSecret);
}


// Pseudo random function using HMAC-SHA 256 
std::string ResponderCrypto::prf(const std::string& keyHex, const std::string& data)
{
    CryptoPP::SecByteBlock keyBytes = hexToSecByteBlock(keyHex);
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(keyBytes, keyBytes.size());
    CryptoPP::SecByteBlock digest(CryptoPP::SHA256::DIGESTSIZE);
    hmac.CalculateDigest(
        digest,
        reinterpret_cast<const CryptoPP::byte*>(data.data()),
        data.size());
    return std::string(reinterpret_cast<const char*>(digest.data()), digest.size());
}

// Function to generate SKEYSEED 
std::string ResponderCrypto::generateSKEYSEED(const std::string& sharedSecret, const std::string& nonceI, const std::string& nonceR)
{
    // Converting hex inputs to binary
    CryptoPP::SecByteBlock ni = hexToSecByteBlock(nonceI);
    CryptoPP::SecByteBlock nr = hexToSecByteBlock(nonceR);

    // Concatenate nonces (Ni || Nr) to create the binary seed
    std::string nonceData;
    nonceData.append(reinterpret_cast<const char*>(ni.data()), ni.size());
    nonceData.append(reinterpret_cast<const char*>(nr.data()), nr.size());

    // Using prf function to calculate HMAC-SHA256
    std::string binarySkeyseed = prf(sharedSecret, nonceData);

    // Converting binary result to hex
    std::string result;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
    encoder.Put(reinterpret_cast<const CryptoPP::byte*>(binarySkeyseed.data()), binarySkeyseed.size());
    encoder.MessageEnd();

    return result;
}

// PRF+ key expansion (Expands a key into arbitrary-length keying material using iterative HMAC) 
std::string ResponderCrypto::prfPlus(const std::string& keyHex, const std::string& seed, size_t desiredLen)
{
    // Convert hex key to raw bytes
    CryptoPP::SecByteBlock keyBytes = hexToSecByteBlock(keyHex);

    CryptoPP::HMAC<CryptoPP::SHA256> hmac(keyBytes, keyBytes.size());
    std::string output;
    output.reserve(desiredLen);

    // T_{i-1} in the RFC text (initially empty)
    std::string tPrev;

    // The block counter (begin with 0x01) 
    unsigned char blockIndex = 1;

    // Keep generating 32-byte blocks until we have enough
    while (output.size() < desiredLen)
    {
        // Input for each iteration: T_{i-1} || seed || block_index
        std::string hmacInput = tPrev + seed + static_cast<char>(blockIndex);

        // Calculate T_i = PRF(Skeyseed, T_{i-1} || seed || block_index)
        std::string t_i = prf(keyHex, hmacInput);

        tPrev = t_i;
        output.append(t_i);
        blockIndex++;
    }

    // Truncate if we collected more than needed and returning in binary format 
    output.resize(desiredLen);
    return output;  
}

void ResponderCrypto::deriveKeys(const std::string& skeyseedHex, const std::string& nonceI,
    const std::string& nonceR, uint64_t spiI, 
    uint64_t spiR, std::string& sk_dHex, std::string& sk_aiHex, 
    std::string& sk_arHex, std::string& sk_eiHex, std::string& sk_erHex)
{
    // Building the seed (nonceI||nonceR||spiI||spiR) 
    std::string seed; 
    CryptoPP::SecByteBlock nonceIBin = hexToSecByteBlock(nonceI);
    seed.append(reinterpret_cast<const char*>(nonceIBin.data()), nonceIBin.size());
    CryptoPP::SecByteBlock nonceRBin = hexToSecByteBlock(nonceR);
    seed.append(reinterpret_cast<const char*>(nonceRBin.data()), nonceRBin.size());
    std::string spiIBin = uint64ToBinary(spiI);
    seed.append(spiIBin);
    std::string spiRBin = uint64ToBinary(spiR);
    seed.append(spiRBin);
    
     // Calculating total key length 
     //    SK_d = 32 byte
     //    SK_ai = 16 byte
     //    SK_ar = 16 byte
     //    SK_ei = 16 byte
     //    SK_er = 16 byte
 
    const size_t totalBytes = 32 + 16 + 16 + 16 + 16; 

    // Generating keychain with formula T1||T2||T3...||Tn = prf+(skeyseed, seed) 
    std::string expanded = prfPlus(skeyseedHex, seed, totalBytes);

    // Splitting all keys from keychain 
    size_t offset = 0;
    auto slice = [&](size_t len) 
    {
        std::string s = expanded.substr(offset, len);
        offset += len;
        return s;
    };

    // SK_d: 32 byte
    std::string raw_sk_d = slice(32);
    // SK_ai (Integrity Initiator, HMAC - SHA - 256): 16 byte
    std::string raw_sk_ai = slice(16);
    // SK_ar (Integrity Responder, HMAC - SHA - 256): 16 byte
    std::string raw_sk_ar = slice(16);
    // SK_ei (Encryption Initiator, AES CBC - 128): 16 byte
    std::string raw_sk_ei = slice(16);
    // SK_er (Encryption Responder, AES CBC - 128): 16 byte
    std::string raw_sk_er = slice(16);

    CryptoPP::SecByteBlock block_sk_d(
        reinterpret_cast<const CryptoPP::byte*>(raw_sk_d.data()), raw_sk_d.size());
    CryptoPP::SecByteBlock block_sk_ai(
        reinterpret_cast<const CryptoPP::byte*>(raw_sk_ai.data()), raw_sk_ai.size());
    CryptoPP::SecByteBlock block_sk_ar(
        reinterpret_cast<const CryptoPP::byte*>(raw_sk_ar.data()), raw_sk_ar.size());
    CryptoPP::SecByteBlock block_sk_ei(
        reinterpret_cast<const CryptoPP::byte*>(raw_sk_ei.data()), raw_sk_ei.size());
    CryptoPP::SecByteBlock block_sk_er(
        reinterpret_cast<const CryptoPP::byte*>(raw_sk_er.data()), raw_sk_er.size());

    sk_dHex = secByteBlockToHex(block_sk_d);
    sk_aiHex = secByteBlockToHex(block_sk_ai);
    sk_arHex = secByteBlockToHex(block_sk_ar);
    sk_eiHex = secByteBlockToHex(block_sk_ei);
    sk_erHex = secByteBlockToHex(block_sk_er);
}


std::string ResponderCrypto::DecryptAES_CBC(const std::string& cipherText, const std::string& key, const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE])
{
    std::string recoveredText;

    // Convert hex-encoded key to SecByteBlock
    CryptoPP::SecByteBlock blockKey = hexToSecByteBlock(key);

    // Ensure the key length is valid
    if (blockKey.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Invalid AES-128 key size. Expected 16 bytes.");
    }

    // AES-CBC Decryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
    decryption.SetKeyWithIV(blockKey, blockKey.size(), iv);

    CryptoPP::StringSource(cipherText, true,
        new CryptoPP::StreamTransformationFilter(decryption,
            new CryptoPP::StringSink(recoveredText)
        )
    );
    //// Print the ciphertext in hexadecimal format
    //printf("Plaintext: ");
    //for (size_t i = 0; i < recoveredText.size(); ++i) {
    //    printf("%02x ", static_cast<unsigned char>(recoveredText[i]));
    //}
    //printf("\n");

    return recoveredText;
}

std::string ResponderCrypto::EncryptAES_CBC(const std::string& plainText, const std::string& key, const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE])
{
    std::string cipherText;

    // Convert hex-encoded key to SecByteBlock
    CryptoPP::SecByteBlock blockKey = hexToSecByteBlock(key);


    // Ensure the key length is valid
    if (blockKey.size() != CryptoPP::AES::DEFAULT_KEYLENGTH)
    {
        throw std::runtime_error("Invalid AES-128 key size. Expected 16 bytes.");
    }

    // AES-CBC Encryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
    encryption.SetKeyWithIV(blockKey, blockKey.size(), iv);

    CryptoPP::StringSource(plainText, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::StringSink(cipherText)
        )
    );

    return cipherText;
}

void ResponderCrypto::GenerateIV(CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE])
{
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
}


