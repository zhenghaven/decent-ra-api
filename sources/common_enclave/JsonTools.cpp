#include "../common/JsonTools.h"

#include <string>
#include <cstring>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

bool ParseStr2Json(rapidjson::Value& outJson, const std::string& inStr)
{
	rapidjson::Document jsonDoc;
	jsonDoc.Parse(inStr.c_str());
	rapidjson::ParseErrorCode errcode = jsonDoc.GetParseError();
	outJson.Swap(jsonDoc);
	
	return errcode == rapidjson::ParseErrorCode::kParseErrorNone;
}

bool ParseStr2Json(rapidjson::Value& outJson, const char* inStr)
{
	rapidjson::Document jsonDoc;
	jsonDoc.Parse(inStr);
	rapidjson::ParseErrorCode errcode = jsonDoc.GetParseError();
	outJson.Swap(jsonDoc);

	return errcode == rapidjson::ParseErrorCode::kParseErrorNone;
}

std::string Json2StyleString(const rapidjson::Value & inJson)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	inJson.Accept(writer);

	return buffer.GetString();
}

void JsonCommonSetString(JSON_EDITION::Value & outJson, const std::string & inStr)
{
	rapidjson::Document document;
	outJson.SetString(inStr.c_str(), inStr.size(), document.GetAllocator());
}
