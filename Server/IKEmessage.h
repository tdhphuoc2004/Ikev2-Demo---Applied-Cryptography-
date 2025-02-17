#pragma once
#include "IKEHeader.h"
#include "IKEPayload.h"
#include <vector>

struct IKEMessage {
    IKEHeader header;
    std::vector<IKEPayload> payloads; // List of IKE payloads (SA, KE, Ni, etc.)

    std::vector<uint8_t> toByteArray(); // Convert full IKE message to binary
    
    bool parseIKEmessage(const std::vector<uint8_t>& rawData); 
};
