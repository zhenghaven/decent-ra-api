#include "../../Common/Tools/JsonTools.h"

#include <string>
#include <cstring>

#include <json/json.h>

#include "../../Common/Common.h"

using namespace Decent;

bool Tools::ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outJson, const std::string& inStr)
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

bool Tools::ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outJson, const char* inStr)
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

std::string Tools::Json2StyledString(const Json::Value & inJson)
{
	return inJson.toStyledString();
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string& index, const std::string& val)
{
	return (doc[index.c_str()] = val);
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, JSON_EDITION::Value & val)
{
	return (doc[index.c_str()] = val);
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const int val)
{
	return (doc[index.c_str()] = val);
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const double val)
{
	return (doc[index.c_str()] = val);
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const bool val)
{
	return (doc[index.c_str()] = val);
}
