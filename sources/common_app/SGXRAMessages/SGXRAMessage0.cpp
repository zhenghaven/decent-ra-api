#include "SGXRAMessage0.h"

#include <memory>
#include <climits>

SGXRAMessage0Send::SGXRAMessage0Send(uint32_t exGrpID) :
	m_exGrpID(exGrpID)
{
	m_isValid = true;
}

SGXRAMessage0Send::SGXRAMessage0Send(Json::Value& msg)
{
	if (msg.isMember("MsgType")
		&& msg["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& msg.isMember("Untrusted")
		&& msg["Untrusted"].isMember("ExGroupID"))
	{
		int64_t tmp = msg["Untrusted"]["ExGroupID"].asInt64();
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

std::string SGXRAMessage0Send::ToJsonString() const
{
	Json::Value jsonRoot;
	Json::Value jsonUntrusted;

	jsonUntrusted["ExGroupID"] = m_exGrpID;

	jsonRoot["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	jsonRoot["Untrusted"] = jsonUntrusted;
	jsonRoot["Trusted"] = Json::nullValue;

	return jsonRoot.toStyledString();
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

SGXRAMessage0Resp::SGXRAMessage0Resp(bool isAccepted) :
	m_isAccepted(isAccepted)
{
	m_isValid = true;
}

SGXRAMessage0Resp::SGXRAMessage0Resp(Json::Value& msg)
{
	if (msg.isMember("MsgType")
		&& msg["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& msg.isMember("Untrusted")
		&& msg["Untrusted"].isMember("IsAccepted"))
	{
		m_isAccepted = msg["Untrusted"]["IsAccepted"].asBool();
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

std::string SGXRAMessage0Resp::ToJsonString() const
{
	Json::Value jsonRoot;
	Json::Value jsonUntrusted;

	jsonUntrusted["IsAccepted"] = m_isAccepted;

	jsonRoot["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	jsonRoot["Untrusted"] = jsonUntrusted;
	jsonRoot["Trusted"] = Json::nullValue;

	return jsonRoot.toStyledString();
}

SGXRAMessage::Type SGXRAMessage0Resp::GetType() const
{
	return SGXRAMessage::Type::MSG0_RESP;
}

bool SGXRAMessage0Resp::IsResp() const
{
	return true;
}

bool SGXRAMessage0Resp::IsAccepted() const
{
	return m_isAccepted;
}
