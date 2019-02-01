#pragma once

#include <string>
#include <vector>

#ifdef ENCLAVE_ENVIRONMENT
#define JSON_EDITION rapidjson
#define JSON_DOCUMENT_TYPE Document

#define JSON_HAS_MEMBER HasMember
#define JSON_IS_OBJECT IsObject
#define JSON_IS_STRING IsString
#define JSON_IS_INT IsInt
#define JSON_IS_DOUBLE IsDouble
#define JSON_IS_NUMBER IsNumber
#define JSON_IS_ARRAY IsArray
#define JSON_AS_STRING GetString
#define JSON_AS_CSTRING JSON_AS_STRING
#define JSON_AS_INT32 GetInt
#define JSON_AS_DOUBLE GetDouble
#define JSON_IT_BEGIN MemberBegin
#define JSON_IT_END MemberEnd
#define JSON_IT_GETKEY(X) (X->name)
#define JSON_IT_GETVALUE(X) (X->value)
#define JSON_ARR_BEGIN GetArray().begin
#define JSON_ARR_END GetArray().end
#define JSON_ARR_GETVALUE(X) (*X)
#else
#define JSON_EDITION Json
#define JSON_DOCUMENT_TYPE Value

#define JSON_HAS_MEMBER isMember
#define JSON_IS_OBJECT isObject
#define JSON_IS_STRING isString
#define JSON_IS_INT isInt
#define JSON_IS_DOUBLE isDouble
#define JSON_IS_NUMBER isNumeric
#define JSON_IS_ARRAY isArray
#define JSON_AS_STRING asString
#define JSON_AS_CSTRING asCString
#define JSON_AS_INT32 asInt
#define JSON_AS_DOUBLE asDouble
#define JSON_IT_BEGIN begin
#define JSON_IT_END end
#define JSON_IT_GETKEY(X) (X.key())
#define JSON_IT_GETVALUE(X) (*X)
#define JSON_ARR_BEGIN JSON_IT_BEGIN
#define JSON_ARR_END JSON_IT_END
#define JSON_ARR_GETVALUE(X) JSON_IT_GETVALUE(X)
#endif

#ifdef ENCLAVE_ENVIRONMENT
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
#endif // ENCLAVE_ENVIRONMENT

namespace Decent
{
	namespace Tools
	{
		bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const std::string& inStr);

		bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const char* inStr);

		std::string Json2StyledString(const JSON_EDITION::Value& inJson);

		JSON_EDITION::Value& JsonConstructArray(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, std::vector<JSON_EDITION::Value>& vals);

		JSON_EDITION::Value& JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, const std::string& val);
		inline JSON_EDITION::Value& JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, const char* val)
		{
			return Decent::Tools::JsonSetVal(doc, index, std::string(val));
		}

		JSON_EDITION::Value& JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, JSON_EDITION::Value& val);

		JSON_EDITION::Value& JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, const int val);
		JSON_EDITION::Value& JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, const double val);
		JSON_EDITION::Value& JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, const bool val);
	}
}
