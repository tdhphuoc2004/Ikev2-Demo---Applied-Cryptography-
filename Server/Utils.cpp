#include <string>
#include <iostream>
#include <bitset>
#include <iomanip>

#include <cryptlib.h>
#include <dh.h>
#include <osrng.h>
#include <hex.h>
#include <string>
#include <eccrypto.h>
#include <oids.h>
#include "Utils.h"

std::string uint64ToBinary(uint64_t value)
{
    std::string result(8, 0);


    for (int i = 0; i < 8; i++) {
        result[i] = static_cast<char>((value >> (56 - (i * 8))) & 0xFF);
    }

    return result;
}

uint64_t binaryToUint64(const std::string& binaryStr)
{

    if (binaryStr.size() < 8) {
        throw std::runtime_error("Binary string too short for uint64_t conversion");
    }

    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | (static_cast<unsigned char>(binaryStr[i]) & 0xFF);
    }

    return result;
}

std::vector<uint8_t> stringToVector(const std::string& str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string vectorToString(const std::vector<uint8_t>& vec)
{
    return std::string(vec.begin(), vec.end());
}

void printBinaryAsBin(const std::string& binaryStr)
{
    for (unsigned char c : binaryStr) {
        std::cout << std::bitset<8>(c) << " ";
    }
    std::cout << std::endl;
}

void printBinaryAsHex(const std::string& binaryStr) {
    std::cout << "Binary data [" << binaryStr.size() << " bytes]: ";
    for (unsigned char c : binaryStr) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(c) << " ";
    }
    std::cout << std::dec << std::endl;
}

// Convert Hex-Encoded String to SecByteBlock
CryptoPP::SecByteBlock hexToSecByteBlock(const std::string& hexStr)
{
    CryptoPP::SecByteBlock byteBlock(hexStr.size() / 2); // Each byte = 2 hex chars

    CryptoPP::StringSource(hexStr, true,
        new CryptoPP::HexDecoder
        (
            new CryptoPP::ArraySink(byteBlock, byteBlock.size())
        )
    );

    return byteBlock;
}

// Convert SecByteBlock to Hex String
std::string secByteBlockToHex(const CryptoPP::SecByteBlock& byteBlock)
{
    std::string hexStr;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexStr));
    encoder.Put(byteBlock, byteBlock.size());
    encoder.MessageEnd();

    return hexStr;
}

void printHexVector(const std::vector<uint8_t>& data)
{
 
    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
        if ((i + 1) % 16 == 0) std::cout << " ";
    }

    std::cout << std::dec << std::endl; // Quay l?i h? ??m th?p phân sau khi in
}
