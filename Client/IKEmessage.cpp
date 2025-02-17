#include "IKEmessage.h"

std::vector<uint8_t> IKEMessage::toByteArray() {
    std::vector<uint8_t> binaryMessage = header.toByteArray();

    for (auto payload : payloads) {
        std::vector<uint8_t> payloadData = payload.toByteArray();
        binaryMessage.insert(binaryMessage.end(), payloadData.begin(), payloadData.end());
    }

    return binaryMessage;
}