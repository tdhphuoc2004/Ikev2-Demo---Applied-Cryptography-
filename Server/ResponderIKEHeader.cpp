#include "ResponderIKEHeader.h"
#include <random>

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
uint64_t generateSPI() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1, UINT64_MAX); // Ensure nonzero SPI
    return dist(gen);
}
