#include "InitiatorIKEmessage.h"

std::vector<uint8_t> IKEMessage::toByteArray() {
    std::vector<uint8_t> binaryMessage = header.toByteArray();

    for (auto payload : payloads) {
        std::vector<uint8_t> payloadData = payload.toByteArray();
        binaryMessage.insert(binaryMessage.end(), payloadData.begin(), payloadData.end());
    }

    return binaryMessage;
}

bool IKEMessage::parseIKEmessage(const std::vector<uint8_t>& rawData)
{
    if (rawData.size() < IKE_HEADER_SIZE) {
        std::cerr << "Error: IKE message too short. Expected " << IKE_HEADER_SIZE
            << " bytes, got " << rawData.size() << std::endl;
        return false;
    }

    size_t offset = 0;
    const uint8_t* data = rawData.data();

    // Parse IKE Header
    std::memcpy(&header.initiatorSPI, data + offset, sizeof(uint64_t));
    offset += 8;
    std::memcpy(&header.responderSPI, data + offset, sizeof(uint64_t));
    offset += 8;

    header.nextPayload = data[offset++];
    header.majorVersion = data[offset++];
    header.minorVersion = data[offset++];
    header.exchangeType = data[offset++];
    std::memcpy(&header.messageID, data + offset, sizeof(uint32_t));
    offset += 4;
    std::memcpy(&header.length, data + offset, sizeof(uint32_t));
    offset += 4;

    if (header.length != rawData.size()) {
        std::cerr << "Error: IKE message length mismatch! Expected "
            << header.length << ", got " << rawData.size() << std::endl;
        return false;
    }

    payloads.clear();

    // Parse Payloads
    uint8_t nextPayloadType = header.nextPayload;
    while (nextPayloadType != PAYLOAD_NONE && offset < rawData.size())
    {
        //  std::cout << "Parsing Payload Type: " << static_cast<int>(nextPayloadType) << std::endl;

        if (offset + 4 > rawData.size()) {
            std::cerr << "Error: Payload header truncated at offset " << offset << std::endl;
            return false;
        }

        IKEPayload payload;
        uint8_t savedNextPayload = data[offset];
        payload.nextPayload = data[offset++];

        //     std::cout << "Next payload in chain: " << static_cast<int>(savedNextPayload) << std::endl;

        payload.critical = data[offset++];
        std::memcpy(&payload.payloadLength, data + offset, sizeof(uint16_t));
        offset += 2;

        if (payload.payloadLength < 4) {
            std::cerr << "Error: Invalid payload length " << payload.payloadLength << std::endl;
            return false;
        }

        size_t dataLength = payload.payloadLength - 4;
        if (offset + dataLength > rawData.size()) {
            std::cerr << "Error: Payload data exceeds message bounds. "
                << "Offset: " << offset
                << " Length: " << dataLength
                << " Total: " << rawData.size() << std::endl;
            return false;
        }

        //   std::cout << "Reading " << dataLength << " bytes of payload data" << std::endl;

        std::vector<uint8_t> payloadData(data + offset, data + offset + dataLength);
        offset += dataLength;

        switch (nextPayloadType) {
        case PAYLOAD_KE:
            payload = parseKEPayload(payloadData);
            payload.nextPayload = savedNextPayload;
            break;
        case PAYLOAD_NONCE:
            payload = parseNoncePayload(payloadData);
            payload.nextPayload = savedNextPayload;
            break;
        default:
            payload.data = payloadData;
            break;
        }

        payloads.push_back(payload);
        nextPayloadType = savedNextPayload;
    }

    return true;
}