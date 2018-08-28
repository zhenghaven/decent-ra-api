#pragma once

#include <string>

#ifdef ENCLAVE_CODE
#define JSON_EDITION rapidjson
#define JSON_DOCUMENT_TYPE Document

#define JSON_HAS_MEMBER HasMember
#define JSON_IS_OBJECT IsObject
#define JSON_IS_STRING IsString
#define JSON_AS_STRING GetString
#define JSON_AS_CSTRING JSON_AS_STRING
#else
#define JSON_EDITION Json
#define JSON_DOCUMENT_TYPE Value

#define JSON_HAS_MEMBER isMember
#define JSON_IS_OBJECT isObject
#define JSON_IS_STRING isString
#define JSON_AS_STRING asString
#define JSON_AS_CSTRING asCString
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

	template <typename Encoding, typename Allocator, typename StackAllocator>
	class GenericDocument;

	typedef GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator> > Value;
	typedef GenericDocument<UTF8<char>, MemoryPoolAllocator<CrtAllocator>, CrtAllocator> Document;
}
#else
namespace JSON_EDITION
{
	class Value;
}
#endif // ENCLAVE_CODE


bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const std::string& inStr);

bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const char* inStr);

std::string Json2StyleString(const JSON_EDITION::Value& inJson);

JSON_EDITION::Value& JsonCommonSetString(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, JSON_EDITION::Value& root, const std::string& index, const std::string& inStr);

JSON_EDITION::Value& JsonCommonSetObject(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, JSON_EDITION::Value& root, const std::string& index, JSON_EDITION::Value& inObj);