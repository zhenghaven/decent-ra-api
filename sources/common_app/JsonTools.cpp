#include "../common/JsonTools.h"

#include <string>
#include <cstring>

#include <json/json.h>

#include "../common/CommonTool.h"

bool ParseStr2Json(Json::Value& outJson, const std::string& inStr)
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

bool ParseStr2Json(Json::Value& outJson, const char* inStr)
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

void JsonCommonSetString(JSON_EDITION::Value & outJson, const std::string & inStr)
{
	outJson = inStr;
}
