#include "../../Common/Tools/JsonTools.h"

#include <cstring>

#include <string>
#include <memory>

#include <json/json.h>

#include "../../Common/RuntimeException.h"

using namespace Decent;
using namespace Decent::Tools;

void Tools::ParseStr2Json(JsonDoc& outJson, const std::string& inStr)
{
	bool isValid = false;
	std::string errStr;
	try
	{
		Json::CharReaderBuilder rbuilder;
		rbuilder["collectComments"] = false;

		std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
		isValid = reader->parse(inStr.c_str(), inStr.c_str() + inStr.size(), &outJson, &errStr);
	}
	catch (const std::bad_alloc)
	{ //We run out of space, there is nothing we can do...
		throw;
	}
	catch (const std::exception& e)
	{
		std::string errStrFinal = "JsonCpp parse error: ";
		errStrFinal += e.what();
		throw RuntimeException(errStrFinal);

	}
	if (!isValid)
	{
		std::string errStrFinal = "JsonCpp parse error: " + errStr;
		throw RuntimeException(errStrFinal);
	}
}

void Tools::ParseStr2Json(JsonDoc& outJson, const char* inStr)
{
	bool isValid = false;
	std::string errStr;
	try
	{
		Json::CharReaderBuilder rbuilder;
		rbuilder["collectComments"] = false;

		std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());

		isValid = reader->parse(inStr, inStr + std::strlen(inStr), &outJson, &errStr);
	}
	catch (const std::bad_alloc)
	{
		throw;
	}
	catch (const std::exception& e)
	{
		std::string errStrFinal = "JsonCpp parse error: ";
		errStrFinal += e.what();
		throw RuntimeException(errStrFinal);

	}
	if (!isValid)
	{
		std::string errStrFinal = "JsonCpp parse error: " + errStr;
		throw RuntimeException(errStrFinal);
	}
}

std::string Tools::Json2StyledString(const Json::Value & inJson)
{
	return inJson.toStyledString();
}

std::string Tools::Json2String(const Json::Value & inJson)
{
	Json::StreamWriterBuilder builder;

	builder["commentStyle"] = "All";
	builder["indentation"] = "";

	return Json::writeString(builder, inJson);
}

JsonValue& Tools::JsonConstructArray(JsonDoc& doc, std::vector<JsonValue>& vals)
{
	doc = Json::arrayValue;
	doc.resize(static_cast<Json::ArrayIndex>(vals.size()));
	for (Json::ArrayIndex i = 0; i < static_cast<Json::ArrayIndex>(vals.size()); ++i)
	{
		doc[i] = vals[i];
	}
	vals.clear();

	return doc;
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string& index, const std::string& val)
{
	return (doc[index.c_str()] = val);
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, JsonValue & val)
{
	return (doc[index.c_str()] = val);
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const int val)
{
	return (doc[index.c_str()] = val);
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const double val)
{
	return (doc[index.c_str()] = val);
}

JsonValue& Tools::JsonSetVal(JsonDoc& doc, const std::string & index, const bool val)
{
	return (doc[index.c_str()] = val);
}
