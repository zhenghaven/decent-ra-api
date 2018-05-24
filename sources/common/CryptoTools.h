#pragma once

#include <string>

#include <sgx_tcrypto.h>

std::string SerializePubKey(const sgx_ec256_public_t& pubKey);

void DeserializePubKey(const std::string& inPubKeyStr, sgx_ec256_public_t& outPubKey);