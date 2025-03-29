#include <hmac.h>
#include <sha.h>
#include <filters.h>
#include <cryptlib.h>
#include <vector>
#include <stdexcept>
#include <hex.h>
#include <secblock.h>
#include <string>
std::vector<uint8_t> signData(const std::string& hexAuthKey, const std::vector<uint8_t>& dataToSign)
{
    std::string decodedKey;
    CryptoPP::StringSource ssHex(hexAuthKey, true,
        new CryptoPP::HexDecoder
        (
            new CryptoPP::StringSink(decodedKey)
        )
    );

    CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(decodedKey.data()), decodedKey.size());

    CryptoPP::HMAC<CryptoPP::SHA256> hmac(key.data(), key.size());

    std::string mac;
    CryptoPP::StringSource ss(dataToSign.data(), dataToSign.size(), true,
        new CryptoPP::HashFilter
        (hmac,
            new CryptoPP::StringSink(mac),
            false,
            16
        )
    );

    return std::vector<uint8_t>(mac.begin(), mac.end());
}