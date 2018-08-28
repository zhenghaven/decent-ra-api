#include "DataCoding.h"

#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <algorithm>
#include <cstring>
#include <vector>

#include <sgx_tcrypto.h>
#include <sgx_ecp_types.h>

#include <cppcodec/base64_rfc4648.hpp>


std::string SerializePubKey(const sgx_ec256_public_t & pubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	memcpy(buffer.data(), &pubKey, sizeof(sgx_ec256_public_t));

	return cppcodec::base64_rfc4648::encode(buffer);
}

void DeserializePubKey(const std::string & inPubKeyStr, sgx_ec256_public_t & outPubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inPubKeyStr);

	memcpy(&outPubKey, buffer.data(), sizeof(sgx_ec256_public_t));
}

std::string SerializeStruct(const void * ptr, size_t size)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(ptr), size);
}

void DeserializeStruct(void* bufferPtr, size_t bufferSize, const std::string& inStr)
{
	std::vector<uint8_t> buffer(bufferSize, 0);
	cppcodec::base64_rfc4648::decode(buffer, inStr);
	
	const size_t neededSize = bufferSize <= buffer.size() ? bufferSize : buffer.size();
	memcpy(bufferPtr, buffer.data(), neededSize);
}

void DeserializeStruct(std::vector<uint8_t>& outData, const std::string& inStr)
{
	cppcodec::base64_rfc4648::decode(outData, inStr);
}

