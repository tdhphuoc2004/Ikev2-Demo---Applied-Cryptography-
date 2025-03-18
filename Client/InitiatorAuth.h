#pragma once
#include <cryptlib.h>
#include <rsa.h>
#include <sha.h>
#include <hex.h>

#include <vector>
#include <stdexcept>
#include <cstdint>

std::vector<uint8_t> signData(const std::string& hexPrivateKey, const std::vector<uint8_t>& dataToSign);