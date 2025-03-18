
#include <vector>
#include <stdexcept>

#include <cstdint>
#include <cryptlib.h>
#include <rsa.h>
#include <sha.h>
#include <hex.h>

std::vector<uint8_t> signData(const std::string& hexPrivateKey, const std::vector<uint8_t>& dataToSign)
{
    //using namespace CryptoPP;

    //// Convert hex string to byte array
    //SecByteBlock privateKeyBytes;
    //StringSource(hexPrivateKey, true, new HexDecoder(new ArraySink(privateKeyBytes, privateKeyBytes.size())));

    //// Load private key from byte array
    //RSA::PrivateKey privateKey;
    //privateKey.Load(StringSource(privateKeyBytes, privateKeyBytes.size(), true).Ref());

    //// Prepare the signer with the RSA private key
    //RSASSA_PKCS1v15_SHA256 signer;
    //signer.AccessPrivateKey() = privateKey;

    //// Create a vector to store the signature
    //std::vector<uint8_t> signature(signer.MaxSignatureLength());
    //unsigned int signatureLength = signature.size();

    //// Sign the data
    //try {
    //    signer.SignMessage(RandomNumberGenerator(), dataToSign.data(), dataToSign.size(), signature.data());
    //    signature.resize(signatureLength); // Adjust the size of the signature to fit
    //}
    //catch (const Exception& e) {
    //    throw std::runtime_error("Signing failed: " + std::string(e.what()));
    //}

    //return signature;
    return std::vector<uint8_t>(); 
}