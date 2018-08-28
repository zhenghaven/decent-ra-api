#include "SGXRAMessage0.h"

#include <json/json.h>

#include "../../MessageException.h"

constexpr char SGXRAMessage0Send::sk_LabelExGroupId[];
constexpr char SGXRAMessage0Send::sk_ValueType[];

uint32_t SGXRAMessage0Send::ParseExGroupID(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage0Send::sk_LabelExGroupId) && SGXRASPRoot[SGXRAMessage0Send::sk_LabelExGroupId].isUInt())
	{
		return SGXRASPRoot[SGXRAMessage0Send::sk_LabelExGroupId].asUInt();
	}
	throw MessageParseException();
}

SGXRAMessage0Send::SGXRAMessage0Send(const std::string& senderID, uint32_t exGrpID) :
	SGXRASPMessage(senderID),
	m_exGrpID(exGrpID)
{
}

SGXRAMessage0Send::SGXRAMessage0Send(const Json::Value& msg) :
	SGXRASPMessage(msg, sk_ValueType),
	m_exGrpID(ParseExGroupID(msg[Messages::sk_LabelRoot][SGXRASPMessage::sk_LabelRoot]))
{
}

SGXRAMessage0Send::~SGXRAMessage0Send()
{
}

std::string SGXRAMessage0Send::GetMessageTypeStr() const
{
	return sk_ValueType;
}

uint32_t SGXRAMessage0Send::GetExtendedGroupID() const
{
	return m_exGrpID;
}

Json::Value& SGXRAMessage0Send::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelExGroupId] = m_exGrpID;

	return parent;
}

constexpr char SGXRAMessage0Resp::sk_LabelPubKey[];
constexpr char SGXRAMessage0Resp::sk_ValueType[];

std::string SGXRAMessage0Resp::ParsePublicKey(const Json::Value & SGXRAClientRoot)
{
	if (SGXRAClientRoot.isMember(SGXRAMessage0Resp::sk_LabelPubKey) && SGXRAClientRoot[SGXRAMessage0Resp::sk_LabelPubKey].isString())
	{
		return SGXRAClientRoot[SGXRAMessage0Resp::sk_LabelPubKey].asString();
	}
	throw MessageParseException();
}

SGXRAMessage0Resp::SGXRAMessage0Resp(const std::string& senderID, const std::string& pubKeyBase64) :
	SGXRAClientMessage(senderID),
	m_pubKey(pubKeyBase64)
{
}

SGXRAMessage0Resp::SGXRAMessage0Resp(const Json::Value& msg) :
	SGXRAClientMessage(msg, sk_ValueType),
	m_pubKey(ParsePublicKey(msg[Messages::sk_LabelRoot][SGXRAClientMessage::sk_LabelRoot]))
{
}

SGXRAMessage0Resp::~SGXRAMessage0Resp()
{
}

std::string SGXRAMessage0Resp::GetMessageTypeStr() const
{
	return sk_ValueType;
}

std::string SGXRAMessage0Resp::GetRAPubKey() const
{
	return m_pubKey;
}

Json::Value & SGXRAMessage0Resp::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	//parent[SGXRAClientMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelPubKey] = m_pubKey;

	return parent;
}
