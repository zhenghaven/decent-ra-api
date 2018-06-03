#include "SGXRAMessage0.h"

#include <memory>
#include <climits>

SGXRAMessage0Send::SGXRAMessage0Send(const std::string& senderID, uint32_t exGrpID) :
	SGXRAMessage(senderID),
	m_exGrpID(exGrpID)
{
	m_isValid = true;
}

SGXRAMessage0Send::SGXRAMessage0Send(Json::Value& msg) :
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
		&& root["MsgType"].asString() == SGXRAMessage::GetMessageTypeStr(GetType())
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("ExGroupID"))
	{
		int64_t tmp = root["Untrusted"]["ExGroupID"].asInt64();
		if (0 <= tmp && tmp <= UINT32_MAX)
		{
			m_exGrpID = static_cast<uint32_t>(tmp);
			m_isValid = true;
		}
		else
		{
			m_isValid = false;
		}
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessage0Send::~SGXRAMessage0Send()
{
}

std::string SGXRAMessage0Send::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
}

SGXRAMessage::Type SGXRAMessage0Send::GetType() const
{
	return SGXRAMessage::Type::MSG0_SEND;
}

bool SGXRAMessage0Send::IsResp() const
{
	return false;
}

uint32_t SGXRAMessage0Send::GetExtendedGroupID() const
{
	return m_exGrpID;
}

Json::Value& SGXRAMessage0Send::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["ExGroupID"] = m_exGrpID;

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}

SGXRAMessage0Resp::SGXRAMessage0Resp(const std::string& senderID, const std::string& pubKeyBase64) :
	SGXRAMessage(senderID),
	m_pubKey(pubKeyBase64)
{
	m_isValid = true;
}

SGXRAMessage0Resp::SGXRAMessage0Resp(Json::Value& msg) :
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
		&& root["MsgType"].asString() == SGXRAMessage::GetMessageTypeStr(GetType())
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("RAPubKey"))
	{
		m_pubKey = root["Untrusted"]["RAPubKey"].asString();
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessage0Resp::~SGXRAMessage0Resp()
{
}

std::string SGXRAMessage0Resp::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
}

SGXRAMessage::Type SGXRAMessage0Resp::GetType() const
{
	return SGXRAMessage::Type::MSG0_RESP;
}

bool SGXRAMessage0Resp::IsResp() const
{
	return true;
}

std::string SGXRAMessage0Resp::GetRAPubKey() const
{
	return m_pubKey;
}

Json::Value & SGXRAMessage0Resp::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["RAPubKey"] = m_pubKey;

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
