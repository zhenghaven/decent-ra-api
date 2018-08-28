#include "Messages.h"

#include <json/json.h>

#include "MessageException.h"

std::string Messages::ParseSenderID(const Json::Value& msg)
{
	if (msg.isMember(Messages::sk_LabelRoot) && msg[Messages::sk_LabelRoot].isObject()
		&& msg[Messages::sk_LabelRoot].isMember(Messages::sk_LabelSender) && msg[Messages::sk_LabelRoot][Messages::sk_LabelSender].isString())
	{
		return msg[Messages::sk_LabelRoot][Messages::sk_LabelSender].asString();
	}
	throw MessageParseException();
}

std::string Messages::ParseCat(const Json::Value& msg)
{
	if (msg.isMember(Messages::sk_LabelRoot) && msg[Messages::sk_LabelRoot].isObject()
		&& msg[Messages::sk_LabelRoot].isMember(Messages::sk_LabelCategory) && msg[Messages::sk_LabelRoot][Messages::sk_LabelCategory].isString())
	{
		return msg[Messages::sk_LabelRoot][Messages::sk_LabelCategory].asString();
	}
	throw MessageParseException();
}

Messages::Messages(const std::string& senderID) :
	m_senderID(senderID)
{}

Messages::Messages(const Json::Value& msg, const char* expectedCat) :
	m_senderID(ParseSenderID(msg))
{
	if (expectedCat && ParseCat(msg) != expectedCat)
	{
		throw MessageParseException();
	}
}

const std::string & Messages::GetSenderID() const
{
	return m_senderID;
}

std::string Messages::ToJsonString() const
{
	Json::Value jsonRoot;

	GetJsonMsg(jsonRoot);

	return jsonRoot.toStyledString();
}

Json::Value& Messages::GetJsonMsg(Json::Value& outJson) const
{
	outJson[sk_LabelRoot] = Json::objectValue;
	outJson[sk_LabelRoot][sk_LabelSender] = m_senderID;
	outJson[sk_LabelRoot][sk_LabelCategory] = GetMessageCategoryStr();

	return outJson[sk_LabelRoot];
}
