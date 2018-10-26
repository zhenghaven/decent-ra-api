#include "../common/JsonTools.h"

#include <string>
#include <cstring>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include "Common.h"

bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const std::string& inStr)
{
	outDoc.Parse(inStr.c_str());
	rapidjson::ParseErrorCode errcode = outDoc.GetParseError();
	
	return errcode == rapidjson::ParseErrorCode::kParseErrorNone;
}

bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const char* inStr)
{
	outDoc.Parse(inStr);
	rapidjson::ParseErrorCode errcode = outDoc.GetParseError();

	return errcode == rapidjson::ParseErrorCode::kParseErrorNone;
}

std::string Json2StyleString(const rapidjson::Value & inJson)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	inJson.Accept(writer);

	std::string res(buffer.GetString());
	return res;
}

JSON_EDITION::Value& JsonCommonSetString(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, JSON_EDITION::Value & root, const std::string & index, const std::string & inStr)
{
	if (!root.IsObject())
	{
		root.SetObject();
	}
	if (!root.HasMember(index.c_str()))
	{
		root.AddMember(rapidjson::StringRef(index.c_str(), index.size()), rapidjson::Value().SetNull(), doc.GetAllocator());
	}
	return (root[index.c_str()].SetString(rapidjson::StringRef(inStr.c_str(), inStr.size()), doc.GetAllocator()));
}

JSON_EDITION::Value& JsonCommonSetObject(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, JSON_EDITION::Value & root, const std::string & index, JSON_EDITION::Value & inObj)
{
	if (!root.IsObject())
	{
		root.SetObject();
	}
	if (!root.HasMember(index.c_str()))
	{
		root.AddMember(rapidjson::StringRef(index.c_str(), index.size()), rapidjson::Value().SetNull(), doc.GetAllocator());
	}
	return (root[index.c_str()] = inObj);
}
