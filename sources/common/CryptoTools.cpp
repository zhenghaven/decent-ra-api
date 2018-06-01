#include "CryptoTools.h"

#include <vector>

#include <cppcodec/base64_rfc4648.hpp>

std::string SerializePubKey(const sgx_ec256_public_t & pubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	memcpy(&buffer[0], &pubKey, sizeof(sgx_ec256_public_t));

	return cppcodec::base64_rfc4648::encode(buffer);
}

void DeserializePubKey(const std::string & inPubKeyStr, sgx_ec256_public_t & outPubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inPubKeyStr);

	memcpy(&outPubKey, buffer.data(), sizeof(sgx_ec256_public_t));
}
