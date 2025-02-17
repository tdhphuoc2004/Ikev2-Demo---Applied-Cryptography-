#pragma once
#include <cstdint>
#include <vector>

#define IKE_SA_INIT 34
#define IKE_AUTH 35
#define CREATE_CHILD_SA 36
#define INFORMATIONAL 37

#define IKE_HEADER_SIZE 28  // Fixed size of IKE header

struct IKEHeader {
    uint64_t initiatorSPI;
    uint64_t responderSPI;
    uint8_t nextPayload;
    uint8_t majorVersion;
    uint8_t minorVersion;
    uint8_t exchangeType;
    uint32_t messageID;
    uint32_t length;

    std::vector<uint8_t> toByteArray();
};
uint64_t generateSPI(); 
