#include "ResponderIKEHeader.h"
#include <osrng.h>

std::vector<uint8_t> IKEHeader::toByteArray()
{
    std::vector<uint8_t> buffer(IKE_HEADER_SIZE, 0); // IKE Header is 28 bytes

    std::memcpy(&buffer[0], &initiatorSPI, sizeof(uint64_t));
    std::memcpy(&buffer[8], &responderSPI, sizeof(uint64_t));
    buffer[16] = nextPayload;
    buffer[17] = majorVersion;
    buffer[18] = minorVersion;
    buffer[19] = exchangeType;

    std::memcpy(&buffer[20], &messageID, sizeof(uint32_t));
    std::memcpy(&buffer[24], &length, sizeof(uint32_t));

    return buffer;
}

// Generate a random SPI (8 bytes)
uint64_t generateSPI()
{
    CryptoPP::AutoSeededRandomPool prng;
    uint64_t spi = 0;
    do
    {
        prng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&spi), sizeof(spi));
    } while (spi == 0); // ??m b?o SPI khác 0
    return spi;
}
