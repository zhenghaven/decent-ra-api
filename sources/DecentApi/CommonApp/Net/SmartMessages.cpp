#include "SmartMessages.h"

#include <json/json.h>

#include "MessageException.h"

using namespace Decent::Net;

constexpr char SmartMessages::sk_LabelRoot[];
constexpr char SmartMessages::sk_LabelSender[];
constexpr char SmartMessages::sk_LabelCategory[];
constexpr char SmartMessages::sk_LabelChild[];

std::string SmartMessages::ParseSenderID(const Json::Value& msg)
{
	if (msg.isMember(SmartMessages::sk_LabelRoot))
	{
		const Json::Value& root = msg[SmartMessages::sk_LabelRoot];

		if (root.isObject() && root.isMember(SmartMessages::sk_LabelSender) && root.isMember(SmartMessages::sk_LabelChild) &&
			root[SmartMessages::sk_LabelSender].isString())
		{
			return root[SmartMessages::sk_LabelSender].asString();
		}
	}
	
	throw MessageParseException();
}

std::string SmartMessages::ParseCat(const Json::Value& msg)
{
	if (msg.isMember(SmartMessages::sk_LabelRoot))
	{
		const Json::Value& root = msg[SmartMessages::sk_LabelRoot];

		if (root.isObject() && root.isMember(SmartMessages::sk_LabelCategory) &&
			root[SmartMessages::sk_LabelCategory].isString())
		{
			return root[SmartMessages::sk_LabelCategory].asString();
		}
	}
	
	throw MessageParseException();
}

SmartMessages::SmartMessages() :
	SmartMessages(std::string())
{}

SmartMessages::SmartMessages(const std::string & senderId) :
	m_senderID(senderId)
{
}

SmartMessages::SmartMessages(const Json::Value& msg, const char* expectedCat) :
	m_senderID(ParseSenderID(msg))
{
	if (expectedCat && ParseCat(msg) != expectedCat)
	{
		throw MessageParseException();
	}
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

	Json::Value& root = outJson[sk_LabelRoot];
	root[sk_LabelSender] = m_senderID;
	root[sk_LabelCategory] = GetMessageCategoryStr();
	root[sk_LabelChild] = Json::objectValue;

	return root[sk_LabelChild];
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
