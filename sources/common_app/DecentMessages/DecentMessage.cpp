#include "DecentMessage.h"

DecentMessage::DecentMessage(const std::string & senderID) :
	RAMessages(senderID)
{
}

DecentMessage::DecentMessage(Json::Value & msg) :
	RAMessages(msg)
{
	if (!IsValid())
	{
		return;
	}

	if (!msg.isMember("child")
		|| !msg["child"].isObject())
	{
		m_isValid = false;
		return;
	}

	Json::Value& root = msg["child"];

	if (root.isMember("Type")
		&& root["Type"].isString()
		&& root["Type"].asString() == "Decent")
	{
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

DecentMessage::~DecentMessage()
{
}

std::string DecentMessage::ToJsonString() const
{
	Json::Value jsonRoot;

	GetJsonMsg(jsonRoot);

	return jsonRoot.toStyledString();
}

std::string DecentMessage::GetMessageTypeStr(const Type t)
{
	switch (t)
	{
	case DecentMessage::Type::DECENT_MSG0:
		return "DECENT_MSG0";
	case DecentMessage::Type::DECENT_KEY_REQ:
		return "DECENT_KEY_REQ";
	case DecentMessage::Type::ROOT_NODE_RESP:
		return "ROOT_NODE_RESP";
	case DecentMessage::Type::APPL_NODE_RESP:
		return "APPL_NODE_RESP";
	default:
		return "OTHER";
	}
}

Json::Value & DecentMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = RAMessages::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];
	child["Type"] = "Decent";

	return child;
}
