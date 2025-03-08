#pragma once
#include <string>
#include <iostream>

std::string uint64ToBinary(uint64_t value);
uint64_t binaryToUint64(const std::string& binaryStr);
void printBinaryAsBin(const std::string& binaryStr);
void printBinaryAsHex(const std::string& binaryStr);
CryptoPP::SecByteBlock hexToSecByteBlock(const std::string& hexStr);
std::string secByteBlockToHex(const CryptoPP::SecByteBlock& byteBlock);