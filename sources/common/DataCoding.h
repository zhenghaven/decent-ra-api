#pragma once

#include <string>
#include <vector>

//Forward declarations:
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;

std::string SerializeStruct(const void* ptr, size_t size);
template<typename T>
inline std::string SerializeStruct(const T& data)
{
	return SerializeStruct(&data, sizeof(T));
}

void DeserializeStruct(void* bufferPtr, size_t bufferSize, const std::string& inStr);
void DeserializeStruct(std::vector<uint8_t>& outData, const std::string& inStr);
template<typename T>
inline void DeserializeStruct(T& outData, const std::string& inStr)
{
	DeserializeStruct(static_cast<void*>(&outData), sizeof(T), inStr);
}
