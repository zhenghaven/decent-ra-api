#pragma once

#include <string>
#include <vector>

#include "JsonForwardDeclare.h"

#ifdef ENCLAVE_ENVIRONMENT
//#define JSON_EDITION rapidjson
//#define JSON_DOCUMENT_TYPE Document

#define JSON_HAS_MEMBER HasMember
#define JSON_IS_OBJECT IsObject
#define JSON_IS_STRING IsString
#define JSON_IS_INT IsInt
#define JSON_IS_DOUBLE IsDouble
#define JSON_IS_NUMBER IsNumber
#define JSON_IS_ARRAY IsArray
#define JSON_IS_BOOL IsBool
#define JSON_AS_STRING GetString
#define JSON_AS_CSTRING JSON_AS_STRING
#define JSON_AS_INT32 GetInt
#define JSON_AS_DOUBLE GetDouble
#define JSON_AS_BOOL GetBool
#define JSON_IT_BEGIN MemberBegin
#define JSON_IT_END MemberEnd
#define JSON_IT_GETKEY(X) (X->name)
#define JSON_IT_GETVALUE(X) (X->value)
#define JSON_ARR_BEGIN GetArray().begin
#define JSON_ARR_END GetArray().end
#define JSON_ARR_GETVALUE(X) (*X)
#else
//#define JSON_EDITION Json
//#define JSON_DOCUMENT_TYPE Value

#define JSON_HAS_MEMBER isMember
#define JSON_IS_OBJECT isObject
#define JSON_IS_STRING isString
#define JSON_IS_INT isInt
#define JSON_IS_DOUBLE isDouble
#define JSON_IS_NUMBER isNumeric
#define JSON_IS_ARRAY isArray
#define JSON_IS_BOOL isBool
#define JSON_AS_STRING asString
#define JSON_AS_CSTRING asCString
#define JSON_AS_INT32 asInt
#define JSON_AS_DOUBLE asDouble
#define JSON_AS_BOOL asBool
#define JSON_IT_BEGIN begin
#define JSON_IT_END end
#define JSON_IT_GETKEY(X) (X.key())
#define JSON_IT_GETVALUE(X) (*X)
#define JSON_ARR_BEGIN JSON_IT_BEGIN
#define JSON_ARR_END JSON_IT_END
#define JSON_ARR_GETVALUE(X) JSON_IT_GETVALUE(X)
#endif

namespace Decent
{
	namespace Tools
	{
		/**
		 * \brief	Parse string to JSON document
		 *
		 * \exception	Decent::RuntimeException	Failed to parse the string. There is some format
		 * 											error.
		 * \exception	std::bad_alloc				Thrown by underlying calls.
		 *
		 * \param [in,out]	outDoc	The output JSON document.
		 * \param 		  	inStr 	The input string.
		 */
		void ParseStr2Json(JsonDoc& outDoc, const std::string& inStr);

		/**
		 * \brief	Parse string to JSON document
		 *
		 * \exception	Decent::RuntimeException	Failed to parse the string. There is some format
		 * 											error.
		 *
		 * \param [in,out]	outDoc	The output JSON document.
		 * \param 		  	inStr 	The input string.
		 */
		void ParseStr2Json(JsonDoc& outDoc, const char* inStr);

		std::string Json2StyledString(const JsonValue& inJson);

		std::string Json2String(const JsonValue& inJson);

		JsonValue& JsonConstructArray(JsonDoc& doc, std::vector<JsonValue>& vals);

		JsonValue& JsonSetVal(JsonDoc& doc, const std::string& index, const std::string& val);
		inline JsonValue& JsonSetVal(JsonDoc& doc, const std::string& index, const char* val)
		{
			return Decent::Tools::JsonSetVal(doc, index, std::string(val));
		}

		JsonValue& JsonSetVal(JsonDoc& doc, const std::string& index, JsonValue& val);

		JsonValue& JsonSetVal(JsonDoc& doc, const std::string& index, const int val);
		JsonValue& JsonSetVal(JsonDoc& doc, const std::string& index, const double val);
		JsonValue& JsonSetVal(JsonDoc& doc, const std::string& index, const bool val);
	}
}
