#include "CommonMessages.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif

#include "../Tools/JsonTools.h"

using namespace Decent::Net;
using namespace Decent::Tools;

const JsonValue& CommonJsonMsg::GetMember(const JsonValue & json, const char * label)
{
	if (label && json.JSON_HAS_MEMBER(label))
	{
		return json[label];
	}
	throw MessageParsingException();
}

template<>
bool CommonJsonMsg::ParseValue<bool>(const JsonValue & json)
{
	return json.JSON_IS_BOOL() ? json.JSON_AS_BOOL() : throw MessageParsingException();
}

template<>
int CommonJsonMsg::ParseValue<int>(const JsonValue & json)
{
	return json.JSON_IS_INT() ? json.JSON_AS_INT32() : throw MessageParsingException();
}

template<>
double CommonJsonMsg::ParseValue<double>(const JsonValue & json)
{
	return json.JSON_IS_DOUBLE() ? json.JSON_AS_DOUBLE() : throw MessageParsingException();
}

template<>
std::string CommonJsonMsg::ParseValue<std::string>(const JsonValue & json)
{
	if (json.JSON_IS_STRING()) //Ternary will make a copy of string here, so better not to use ternary here.
	{
		return json.JSON_AS_STRING();
	}
	throw MessageParsingException();
}

std::string CommonJsonMsg::ToString() const
{
	JsonDoc doc;
	ToJson(doc);
	return Tools::Json2String(doc);
}

std::string Decent::Net::CommonJsonMsg::ToStyledString() const
{
	JsonDoc doc;
	ToJson(doc);
	return Tools::Json2StyledString(doc);
}
