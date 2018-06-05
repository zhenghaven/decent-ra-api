#pragma once

#include <string>

//Forward declarations:
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;
struct _sgx_ec256_signature_t;
typedef _sgx_ec256_signature_t sgx_ec256_signature_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

std::string SerializePubKey(const sgx_ec256_public_t& pubKey);

void DeserializePubKey(const std::string& inPubKeyStr, sgx_ec256_public_t& outPubKey);

std::string SerializeSignature(const sgx_ec256_signature_t& sign);

void DeserializeSignature(const std::string& inSignStr, sgx_ec256_signature_t& outSign);

std::string SerializeKey(const sgx_ec_key_128bit_t& key);

void DeserializeKey(const std::string& inPubStr, sgx_ec_key_128bit_t& outKey);