#include "SGXRAMessage.h"

#include <json/json.h>

#include "../../MessageException.h"

constexpr char SGXRAClientMessage::sk_LabelRoot[];
constexpr char SGXRAClientMessage::sk_LabelType[];
constexpr char SGXRAClientMessage::sk_ValueCat[];

std::string SGXRAClientMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(SGXRAClientMessage::sk_LabelRoot) && MsgRootContent[SGXRAClientMessage::sk_LabelRoot].isObject() &&
		MsgRootContent[SGXRAClientMessage::sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[SGXRAClientMessage::sk_LabelRoot][sk_LabelType].isString()
		)
	{
		return MsgRootContent[SGXRAClientMessage::sk_LabelRoot][sk_LabelType].asString();
	}
	throw MessageParseException();
}

SGXRAClientMessage::SGXRAClientMessage(const std::string & senderID) :
	Messages(senderID)
{
}

SGXRAClientMessage::SGXRAClientMessage(const Json::Value & msg, const char* expectedType) :
	Messages(msg, sk_ValueCat)
{
	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
	{
		throw MessageParseException();
	}
}

SGXRAClientMessage::~SGXRAClientMessage()
{
}

std::string SGXRAClientMessage::GetMessageCategoryStr() const
{
	return SGXRAClientMessage::sk_ValueCat;
}

Json::Value & SGXRAClientMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[SGXRAClientMessage::sk_LabelRoot] = Json::objectValue;
	parent[SGXRAClientMessage::sk_LabelRoot][SGXRAClientMessage::sk_LabelType] = GetMessageTypeStr();

	return parent[SGXRAClientMessage::sk_LabelRoot];
}

constexpr char SGXRASPMessage::sk_LabelRoot[];
constexpr char SGXRASPMessage::sk_LabelType[];
constexpr char SGXRASPMessage::sk_ValueCat[];

std::string SGXRASPMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(SGXRASPMessage::sk_LabelRoot) && MsgRootContent[SGXRASPMessage::sk_LabelRoot].isObject() &&
		MsgRootContent[SGXRASPMessage::sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[SGXRASPMessage::sk_LabelRoot][sk_LabelType].isString()
		)
	{
		return MsgRootContent[SGXRASPMessage::sk_LabelRoot][sk_LabelType].asString();
	}
	throw MessageParseException();
}

SGXRASPMessage::SGXRASPMessage(const std::string & senderID) :
	Messages(senderID)
{
}

SGXRASPMessage::SGXRASPMessage(const Json::Value & msg, const char* expectedType) :
	Messages(msg, sk_ValueCat)
{
	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
	{
		throw MessageParseException();
	}
}

SGXRASPMessage::~SGXRASPMessage()
{
}

std::string SGXRASPMessage::GetMessageCategoryStr() const
{
	return SGXRASPMessage::sk_ValueCat;
}

Json::Value & SGXRASPMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[SGXRASPMessage::sk_LabelRoot] = Json::objectValue;
	parent[SGXRASPMessage::sk_LabelRoot][SGXRASPMessage::sk_LabelType] = GetMessageTypeStr();

	return parent[SGXRASPMessage::sk_LabelRoot];
}

constexpr char SGXRAClientErrMsg::sk_LabelErrMsg[];
constexpr char SGXRAClientErrMsg::sk_ValueType[];

std::string SGXRAClientErrMsg::ParseErrorMsg(const Json::Value & SGXRAClientRoot)
{
	if (SGXRAClientRoot.isMember(SGXRAClientErrMsg::sk_LabelErrMsg) && SGXRAClientRoot[SGXRAClientErrMsg::sk_LabelErrMsg].isString())
	{
		return SGXRAClientRoot[SGXRAClientErrMsg::sk_LabelErrMsg].asString();
	}
	throw MessageParseException();
}

SGXRAClientErrMsg::SGXRAClientErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXRAClientMessage(senderID),
	m_errStr(errStr)
{
}

SGXRAClientErrMsg::SGXRAClientErrMsg(const Json::Value & msg) :
	SGXRAClientMessage(msg, sk_ValueType),
	m_errStr(ParseErrorMsg(msg[Messages::sk_LabelRoot][SGXRAClientMessage::sk_LabelRoot]))
{
}

SGXRAClientErrMsg::~SGXRAClientErrMsg()
{
}

std::string SGXRAClientErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const std::string & SGXRAClientErrMsg::GetErrStr() const
{
	return m_errStr;
}

Json::Value & SGXRAClientErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	//parent[SGXRAClientMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = m_errStr;

	return parent;
}

constexpr char SGXRASPErrMsg::sk_LabelErrMsg[];
constexpr char SGXRASPErrMsg::sk_ValueType[];

std::string SGXRASPErrMsg::ParseErrorMsg(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRASPErrMsg::sk_LabelErrMsg) && SGXRASPRoot[SGXRASPErrMsg::sk_LabelErrMsg].isString())
	{
		return SGXRASPRoot[SGXRASPErrMsg::sk_LabelErrMsg].asString();
	}
	throw MessageParseException();
}

SGXRASPErrMsg::SGXRASPErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXRASPMessage(senderID),
	m_errStr(errStr)
{
}

SGXRASPErrMsg::SGXRASPErrMsg(const Json::Value & msg) :
	SGXRASPMessage(msg, sk_ValueType),
	m_errStr(ParseErrorMsg(msg[Messages::sk_LabelRoot][SGXRASPMessage::sk_LabelRoot]))
{
}

SGXRASPErrMsg::~SGXRASPErrMsg()
{
}

std::string SGXRASPErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const std::string & SGXRASPErrMsg::GetErrStr() const
{
	return m_errStr;
}

Json::Value & SGXRASPErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = m_errStr;

	return parent;
}
