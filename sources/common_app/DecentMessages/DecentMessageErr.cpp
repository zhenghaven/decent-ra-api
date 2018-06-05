#include "DecentMessageErr.h"

DecentMessageErr::DecentMessageErr(const std::string & senderID, const std::string& errMsg) :
	DecentMessage(senderID),
	m_errMsg(errMsg)
{
	m_isValid = true;
}

DecentMessageErr::DecentMessageErr(Json::Value & msg) :
	DecentMessage(msg)
{
	if (!IsValid())
	{
		return;
	}

	Json::Value& parent = msg["child"];

	if (!parent.isMember("child")
		|| !parent["child"].isObject())
	{
		m_isValid = false;
		return;
	}

	Json::Value& root = parent["child"];

	if (root.isMember("MsgType")
		&& root["MsgType"].isString()
		&& root["MsgType"].asString() == DecentMessage::GetMessageTypeStr(GetType())
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("ErrMsg")
		&& root["Untrusted"]["ErrMsg"].isString())
	{
		m_errMsg = root["Untrusted"]["ErrMsg"].asString();
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

DecentMessageErr::~DecentMessageErr()
{
}

DecentMessage::Type DecentMessageErr::GetType() const
{
	return DecentMessage::Type::DECENT_ERROR_MSG;
}

std::string DecentMessageErr::GetMessgaeSubTypeStr() const
{
	return DecentMessage::GetMessageTypeStr(GetType());
}

std::string DecentMessageErr::GetErrorMsg() const
{
	return m_errMsg;
}

Json::Value & DecentMessageErr::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["ErrMsg"] = m_errMsg;

	child["MsgType"] = DecentMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
