#include "Messages.h"

#include <json/json.h>

#include "MessageException.h"

std::string Messages::ParseSenderID(const Json::Value& msg)
{
	if (msg.isMember(Messages::LABEL_ROOT) && msg[Messages::LABEL_ROOT].isObject()
		&& msg[Messages::LABEL_ROOT].isMember(Messages::LABEL_SENDER) && msg[Messages::LABEL_ROOT][Messages::LABEL_SENDER].isString())
	{
		return msg[Messages::LABEL_ROOT][Messages::LABEL_SENDER].asString();
	}
	throw MessageParseException();
}

std::string Messages::ParseCat(const Json::Value& msg)
{
	if (msg.isMember(Messages::LABEL_ROOT) && msg[Messages::LABEL_ROOT].isObject()
		&& msg[Messages::LABEL_ROOT].isMember(Messages::LABEL_CATEGORY) && msg[Messages::LABEL_ROOT][Messages::LABEL_CATEGORY].isString())
	{
		return msg[Messages::LABEL_ROOT][Messages::LABEL_CATEGORY].asString();
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
	outJson[LABEL_ROOT] = Json::objectValue;
	outJson[LABEL_ROOT][LABEL_SENDER] = m_senderID;
	outJson[LABEL_ROOT][LABEL_CATEGORY] = GetMessageCategoryStr();

	return outJson[LABEL_ROOT];
}
