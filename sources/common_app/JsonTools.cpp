#include "../common/JsonTools.h"

#include <string>
#include <cstring>

#include <json/json.h>

#include "../common/CommonTool.h"

bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outJson, const std::string& inStr)
{
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
#ifndef NDEBUG
	std::string errStr;
#endif // !NDEBUG

	Json::CharReader* reader = rbuilder.newCharReader();
#ifndef NDEBUG
	bool isValid = reader->parse(inStr.c_str(), inStr.c_str() + inStr.size(), &outJson, &errStr);
	if (!isValid)
	{
		LOGW("Json::CharReader: %s\n", errStr.c_str());
	}
#else
	bool isValid = reader->parse(inStr.c_str(), inStr.c_str() + inStr.size(), &outJson, nullptr);
#endif // !NDEBUG

	delete reader;

	return isValid;
}

bool ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outJson, const char* inStr)
{
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
#ifndef NDEBUG
	std::string errStr;
#endif // !NDEBUG

	Json::CharReader* reader = rbuilder.newCharReader();
#ifndef NDEBUG
	bool isValid = reader->parse(inStr, inStr + std::strlen(inStr), &outJson, &errStr);
	if (!isValid)
	{
		LOGW("Json::CharReader: %s\n", errStr.c_str());
	}
#else
	bool isValid = reader->parse(inStr, inStr + std::strlen(inStr), &outJson, nullptr);
#endif // !NDEBUG

	delete reader;

	return isValid;
}

std::string Json2StyleString(const Json::Value & inJson)
{
	return inJson.toStyledString();
}

JSON_EDITION::Value& JsonCommonSetString(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, Json::Value& root, const std::string& index, const std::string& inStr)
{
	return (root[index.c_str()] = inStr);
}

JSON_EDITION::Value& JsonCommonSetObject(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, Json::Value & root, const std::string & index, JSON_EDITION::Value & inObj)
{
	return (root[index.c_str()] = inObj);
}
