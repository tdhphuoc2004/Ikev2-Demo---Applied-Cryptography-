#pragma once
#include <string>
#include <iostream>

// Convert uint64 to bin 
std::string uint64ToBinary(uint64_t value);
uint64_t binaryToUint64(const std::string& binaryStr);

// Print for debugging
void printBinaryAsBin(const std::string& binaryStr);
void printBinaryAsHex(const std::string& binaryStr);

// Convert hex to bin and viceversa in crypto++ 
CryptoPP::SecByteBlock hexToSecByteBlock(const std::string& hexStr);
std::string secByteBlockToHex(const CryptoPP::SecByteBlock& byteBlock);


std::vector<uint8_t> stringToVector(const std::string& str);
std::string vectorToString(const std::vector<uint8_t>& vec);

void printHexVector(const std::vector<uint8_t>& data);