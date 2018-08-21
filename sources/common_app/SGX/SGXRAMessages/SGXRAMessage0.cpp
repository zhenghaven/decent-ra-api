#include "SGXRAMessage0.h"

#include <json/json.h>

#include "../../MessageException.h"

uint32_t SGXRAMessage0Send::ParseExGroupID(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage0Send::LABEL_EX_GROUP_ID) && SGXRASPRoot[SGXRAMessage0Send::LABEL_EX_GROUP_ID].isUInt())
	{
		return SGXRASPRoot[SGXRAMessage0Send::LABEL_EX_GROUP_ID].asUInt();
	}
	throw MessageParseException();
}

SGXRAMessage0Send::SGXRAMessage0Send(const std::string& senderID, uint32_t exGrpID) :
	SGXRASPMessage(senderID),
	m_exGrpID(exGrpID)
{
}

SGXRAMessage0Send::SGXRAMessage0Send(const Json::Value& msg) :
	SGXRASPMessage(msg),
	m_exGrpID(ParseExGroupID(msg[Messages::LABEL_ROOT][SGXRASPMessage::LABEL_ROOT]))
{
}

SGXRAMessage0Send::~SGXRAMessage0Send()
{
}

std::string SGXRAMessage0Send::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

uint32_t SGXRAMessage0Send::GetExtendedGroupID() const
{
	return m_exGrpID;
}

Json::Value& SGXRAMessage0Send::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_EX_GROUP_ID] = m_exGrpID;

	return parent;
}

std::string SGXRAMessage0Resp::ParsePublicKey(const Json::Value & SGXRAClientRoot)
{
	if (SGXRAClientRoot.isMember(SGXRAMessage0Resp::LABEL_PUB_KEY) && SGXRAClientRoot[SGXRAMessage0Resp::LABEL_PUB_KEY].isString())
	{
		return SGXRAClientRoot[SGXRAMessage0Resp::LABEL_PUB_KEY].asString();
	}
	throw MessageParseException();
}

SGXRAMessage0Resp::SGXRAMessage0Resp(const std::string& senderID, const std::string& pubKeyBase64) :
	SGXRAClientMessage(senderID),
	m_pubKey(pubKeyBase64)
{
}

SGXRAMessage0Resp::SGXRAMessage0Resp(const Json::Value& msg) :
	SGXRAClientMessage(msg),
	m_pubKey(ParsePublicKey(msg[Messages::LABEL_ROOT][SGXRAClientMessage::LABEL_ROOT]))
{
}

SGXRAMessage0Resp::~SGXRAMessage0Resp()
{
}

std::string SGXRAMessage0Resp::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

std::string SGXRAMessage0Resp::GetRAPubKey() const
{
	return m_pubKey;
}

Json::Value & SGXRAMessage0Resp::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	parent[SGXRAClientMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_PUB_KEY] = m_pubKey;

	return parent;
}
