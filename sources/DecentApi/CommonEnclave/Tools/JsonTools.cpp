#include "../../Common/Tools/JsonTools.h"

#include <string>
#include <cstring>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "../../Common/RuntimeException.h"

using namespace Decent;
using namespace Decent::Tools;

namespace
{
	static JsonValue& ConstructIndex(JsonDoc& doc, const std::string & index, rapidjson::Value& val)
	{
		if (!doc.IsObject())
		{
			doc.SetObject();
		}
		if (!doc.HasMember(index.c_str()))
		{
			doc.AddMember(rapidjson::Value().SetString(rapidjson::StringRef(index.c_str(), index.size()), doc.GetAllocator()),
				val, doc.GetAllocator());
		}
		else
		{
			doc[index.c_str()] = val;
		}

		return doc[index.c_str()];
	}
}

const char* GetErrorString(rapidjson::ParseErrorCode code)
{
	switch (code)
	{
	case rapidjson::kParseErrorNone:
		return "No error.";
	case rapidjson::kParseErrorDocumentEmpty:
		return "The document is empty.";
	case rapidjson::kParseErrorDocumentRootNotSingular:
		return "The document root must not follow by other values.";
	case rapidjson::kParseErrorValueInvalid:
		return "Invalid value.";
	case rapidjson::kParseErrorObjectMissName:
		return "Missing a name for object member.";
	case rapidjson::kParseErrorObjectMissColon:
		return "Missing a colon after a name of object member.";
	case rapidjson::kParseErrorObjectMissCommaOrCurlyBracket:
		return "Missing a comma or '}' after an object member.";
	case rapidjson::kParseErrorArrayMissCommaOrSquareBracket:
		return "Missing a comma or ']' after an array element.";
	case rapidjson::kParseErrorStringUnicodeEscapeInvalidHex:
		return "Incorrect hex digit after \\u escape in string.";
	case rapidjson::kParseErrorStringUnicodeSurrogateInvalid:
		return "The surrogate pair in string is invalid.";
	case rapidjson::kParseErrorStringEscapeInvalid:
		return "Invalid escape character in string.";
	case rapidjson::kParseErrorStringMissQuotationMark:
		return "Missing a closing quotation mark in string.";
	case rapidjson::kParseErrorStringInvalidEncoding:
		return "Invalid encoding in string.";
	case rapidjson::kParseErrorNumberTooBig:
		return "Number too big to be stored in double.";
	case rapidjson::kParseErrorNumberMissFraction:
		return "Miss fraction part in number.";
	case rapidjson::kParseErrorNumberMissExponent:
		return "Miss exponent in number.";
	case rapidjson::kParseErrorTermination:
		return "Parsing was terminated.";
	case rapidjson::kParseErrorUnspecificSyntaxError:
		return "Unspecific syntax error.";
	default:
		return "Unknown rapidjson error.";
	}
}

void Tools::ParseStr2Json(JsonDoc& outDoc, const std::string& inStr)
{
	outDoc.Parse(inStr.c_str());
	rapidjson::ParseErrorCode errcode = outDoc.GetParseError();
	
	if (errcode != rapidjson::ParseErrorCode::kParseErrorNone)
	{
		std::string errorStr = "rapidJson parse error: ";
		(errorStr += GetErrorString(errcode)) += ". ";
		throw RuntimeException(errorStr);
	}
}

void Tools::ParseStr2Json(JsonDoc& outDoc, const char* inStr)
{
	outDoc.Parse(inStr);
	rapidjson::ParseErrorCode errcode = outDoc.GetParseError();

	if (errcode != rapidjson::ParseErrorCode::kParseErrorNone)
	{
		std::string errorStr = "rapidJson parse error: ";
		(errorStr += GetErrorString(errcode)) += ". ";
		throw RuntimeException(errorStr);
	}
}

std::string Tools::Json2StyledString(const rapidjson::Value & inJson)
{
	rapidjson::StringBuffer buffer;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
	inJson.Accept(writer);

	std::string res(buffer.GetString());
	return res;
}

std::string Tools::Json2String(const rapidjson::Value & inJson)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	inJson.Accept(writer);

	std::string res(buffer.GetString());
	return res;
}

JsonValue& Tools::JsonConstructArray(JsonDoc& doc, std::vector<JsonValue>& vals)
{
	doc.SetArray();
	doc.Reserve(static_cast<rapidjson::SizeType>(vals.size()), doc.GetAllocator());
	for (JsonValue& val : vals)
	{
		doc.PushBack(val, doc.GetAllocator());
	}
	vals.clear();

	return doc;
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const std::string & val)
{
	return ConstructIndex(doc, index, 
		rapidjson::Value().SetString(rapidjson::StringRef(val.c_str(), val.size()), doc.GetAllocator()));
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, JsonValue & val)
{
	return ConstructIndex(doc, index, val);
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const int val)
{
	return ConstructIndex(doc, index, rapidjson::Value().SetInt(val));
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const double val)
{
	return ConstructIndex(doc, index, rapidjson::Value().SetDouble(val));
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const bool val)
{
	return ConstructIndex(doc, index, rapidjson::Value().SetBool(val));
}
