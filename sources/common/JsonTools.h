#pragma once

#include <string>

#ifdef ENCLAVE_CODE
#define JSON_EDITION rapidjson
#else
#define JSON_EDITION Json
#endif

#ifdef ENCLAVE_CODE
namespace JSON_EDITION
{
	class CrtAllocator;
	template <typename BaseAllocator>
	class MemoryPoolAllocator;
	template <typename Encoding, typename Allocator>
	class GenericValue;
	template<typename CharType>
	struct UTF8;
	typedef GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator> > Value;
}
#else
namespace JSON_EDITION
{
	class Value;
}
#endif // ENCLAVE_CODE


bool ParseStr2Json(JSON_EDITION::Value& outJson, const std::string& inStr);

bool ParseStr2Json(JSON_EDITION::Value& outJson, const char* inStr);

std::string Json2StyleString(const JSON_EDITION::Value& inJson);

void JsonCommonSetString(JSON_EDITION::Value& outJson, const std::string& inStr);
