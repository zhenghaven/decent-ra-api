#include "SGXRAMessageErr.h"

SGXRAMessageErr::SGXRAMessageErr(const std::string& senderID, const std::string& errStr) :
	SGXRAMessage(senderID),
	m_errStr(errStr)
{
	m_isValid = true;
}

SGXRAMessageErr::SGXRAMessageErr(Json::Value& msg) :
	SGXRAMessage(msg)
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
		&& root["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("ErrMsg")
		&& root["Untrusted"]["ErrMsg"].isString())
	{
		m_errStr = root["Untrusted"]["msg1Data"].asString();

		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessageErr::~SGXRAMessageErr()
{
}

std::string SGXRAMessageErr::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
}

SGXRAMessage::Type SGXRAMessageErr::GetType() const
{
	return SGXRAMessage::Type::ERRO_RESP;
}

bool SGXRAMessageErr::IsResp() const
{
	return true;
}

std::string SGXRAMessageErr::GetErrStr() const
{
	return m_errStr;
}

Json::Value & SGXRAMessageErr::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["ErrMsg"] = m_errStr;

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
