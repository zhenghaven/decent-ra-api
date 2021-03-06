#include "DataCoding.h"

#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <algorithm>
#include <cstring>
#include <vector>

#include <cppcodec/base64_rfc4648.hpp>

using namespace Decent;

std::string Tools::SerializeStruct(const void * ptr, size_t size)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(ptr), size);
}

void Tools::DeserializeStruct(void* bufferPtr, size_t bufferSize, const std::string& inStr)
{
	std::vector<uint8_t> buffer(bufferSize, 0);
	cppcodec::base64_rfc4648::decode(buffer, inStr);
	
	const size_t neededSize = bufferSize <= buffer.size() ? bufferSize : buffer.size();
	memcpy(bufferPtr, buffer.data(), neededSize);
}

void Tools::DeserializeStruct(std::vector<uint8_t>& outData, const std::string& inStr)
{
	cppcodec::base64_rfc4648::decode(outData, inStr);
}

