#include "JsonParser.h"

#include <json/json.h>

#include "../../Common/Tools/JsonTools.h"

using namespace Decent;
using namespace Decent::Tools;

const JsonValue & Tools::JsonGetValue(const JsonValue & json, const std::string & label)
{
	if (json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(label))
	{
		return json[label];
	}
	throw JsonParseError();
}

std::string Tools::JsonGetString(const JsonValue & json)
{
	return json.JSON_IS_STRING() ? json.JSON_AS_STRING() : throw JsonParseError();
}

std::string Tools::JsonGetStringFromObject(const JsonValue & json, const std::string & label)
{
	return JsonGetString(JsonGetValue(json, label));
}

uint32_t Tools::JsonGetInt(const JsonValue & json)
{
	return json.JSON_IS_INT() ? json.JSON_AS_INT32() : throw JsonParseError();
}

uint32_t Tools::JsonGetIntFromObject(const JsonValue & json, const std::string & label)
{
	return JsonGetInt(JsonGetValue(json, label));
}

bool Tools::JsonGetBool(const JsonValue & json)
{
	return json.JSON_IS_BOOL() ? json.JSON_AS_BOOL() : throw JsonParseError();
}

bool Tools::JsonGetBoolFromObject(const JsonValue & json, const std::string & label)
{
	return JsonGetBool(JsonGetValue(json, label));
}
