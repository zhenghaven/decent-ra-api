#include "CryptoTools.h"

#include <cstdlib>
#include <vector>

#include <sgx_tcrypto.h>
#include <sgx_ecp_types.h>

#include <cppcodec/base64_rfc4648.hpp>

std::string SerializePubKey(const sgx_ec256_public_t & pubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	std::memcpy(&buffer[0], &pubKey, sizeof(sgx_ec256_public_t));

	return cppcodec::base64_rfc4648::encode(buffer);
}

void DeserializePubKey(const std::string & inPubKeyStr, sgx_ec256_public_t & outPubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inPubKeyStr);

	std::memcpy(&outPubKey, buffer.data(), sizeof(sgx_ec256_public_t));
}

std::string SerializeSignature(const sgx_ec256_signature_t & sign)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const char*>(&sign), sizeof(sgx_ec256_signature_t));
}

void DeserializeSignature(const std::string & inSignStr, sgx_ec256_signature_t & outSign)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_signature_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inSignStr);

	std::memcpy(&outSign, buffer.data(), sizeof(sgx_ec256_signature_t));
}

std::string SerializeKey(const sgx_ec_key_128bit_t & key)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const char*>(&key), sizeof(sgx_ec_key_128bit_t));
}

void DeserializeKey(const std::string & inPubStr, sgx_ec_key_128bit_t & outKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec_key_128bit_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inPubStr);

	std::memcpy(&outKey, buffer.data(), sizeof(sgx_ec_key_128bit_t));
}
