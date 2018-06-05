#pragma once

#include <string>

#include <cppcodec/base64_rfc4648.hpp>

//Forward declarations:
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;
struct _sgx_ec256_signature_t;
typedef _sgx_ec256_signature_t sgx_ec256_signature_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];
#define SGX_AESGCM_MAC_SIZE             16
typedef uint8_t sgx_aes_gcm_128bit_tag_t[SGX_AESGCM_MAC_SIZE];

std::string SerializePubKey(const sgx_ec256_public_t& pubKey);

void DeserializePubKey(const std::string& inPubKeyStr, sgx_ec256_public_t& outPubKey);

std::string SerializeSignature(const sgx_ec256_signature_t& sign);

void DeserializeSignature(const std::string& inSignStr, sgx_ec256_signature_t& outSign);

std::string SerializeKey(const sgx_ec_key_128bit_t& key);

void DeserializeKey(const std::string& inPubStr, sgx_ec_key_128bit_t& outKey);

template<typename T>
std::string SerializeStruct(const T& data)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const char*>(&data), sizeof(T));
}

template<typename T>
void DeserializeStruct(const std::string& inStr, T& outData)
{
	std::vector<uint8_t> buffer(sizeof(T), 0);
	cppcodec::base64_rfc4648::decode(buffer, inStr);

	std::memcpy(&outData, buffer.data(), sizeof(T));
}
