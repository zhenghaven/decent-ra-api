#pragma once

#include <string>

//Forward declarations:
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;
struct _sgx_ec256_signature_t;
typedef _sgx_ec256_signature_t sgx_ec256_signature_t;

std::string SerializePubKey(const sgx_ec256_public_t& pubKey);

void DeserializePubKey(const std::string& inPubKeyStr, sgx_ec256_public_t& outPubKey);

std::string SerializeSignature(const sgx_ec256_signature_t& sign);

void DeserializeSignature(const std::string& inSignStr, sgx_ec256_signature_t& outSign);