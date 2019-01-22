#include "SmartMessages.h"

#include <json/json.h>

#include "MessageException.h"

using namespace Decent::Net;

constexpr char SmartMessages::sk_LabelRoot[];
constexpr char SmartMessages::sk_LabelSender[];
constexpr char SmartMessages::sk_LabelCategory[];

std::string SmartMessages::ParseSenderID(const Json::Value& msg)
{
	if (msg.isMember(SmartMessages::sk_LabelRoot) && msg[SmartMessages::sk_LabelRoot].isObject()
		&& msg[SmartMessages::sk_LabelRoot].isMember(SmartMessages::sk_LabelSender) && msg[SmartMessages::sk_LabelRoot][SmartMessages::sk_LabelSender].isString())
	{
		return msg[SmartMessages::sk_LabelRoot][SmartMessages::sk_LabelSender].asString();
	}
	throw MessageParseException();
}

std::string SmartMessages::ParseCat(const Json::Value& msg)
{
	if (msg.isMember(SmartMessages::sk_LabelRoot) && msg[SmartMessages::sk_LabelRoot].isObject()
		&& msg[SmartMessages::sk_LabelRoot].isMember(SmartMessages::sk_LabelCategory) && msg[SmartMessages::sk_LabelRoot][SmartMessages::sk_LabelCategory].isString())
	{
		return msg[SmartMessages::sk_LabelRoot][SmartMessages::sk_LabelCategory].asString();
	}
	throw MessageParseException();
}

SmartMessages::SmartMessages(const std::string& senderID) :
	m_senderID(senderID)
{}

SmartMessages::SmartMessages(const Json::Value& msg, const char* expectedCat) :
	m_senderID(ParseSenderID(msg))
{
	if (expectedCat && ParseCat(msg) != expectedCat)
	{
		throw MessageParseException();
	}
}

const std::string & SmartMessages::GetSenderID() const
{
	return m_senderID;
}

std::string SmartMessages::ToJsonString() const
{
	Json::Value jsonRoot;

	GetJsonMsg(jsonRoot);

	return jsonRoot.toStyledString();
}

Json::Value& SmartMessages::GetJsonMsg(Json::Value& outJson) const
{
	outJson[sk_LabelRoot] = Json::objectValue;
	outJson[sk_LabelRoot][sk_LabelSender] = m_senderID;
	outJson[sk_LabelRoot][sk_LabelCategory] = GetMessageCategoryStr();

	return outJson[sk_LabelRoot];
}

constexpr char ErrorMessage::sk_LabelErrMsg[];
constexpr char ErrorMessage::sk_ValueType[];

std::string ErrorMessage::ParseErrorMsg(const Json::Value & typeRoot)
{
	if (typeRoot.isMember(sk_LabelErrMsg) && typeRoot[sk_LabelErrMsg].isString())
	{
		return typeRoot[sk_LabelErrMsg].asString();
	}
	throw MessageParseException();
}
