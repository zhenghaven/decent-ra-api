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

SGXRAClientErrMsg::SGXRAClientErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXRAClientMessage(senderID),
	ErrorMessage(errStr)
{
}

SGXRAClientErrMsg::SGXRAClientErrMsg(const Json::Value & msg) :
	SGXRAClientMessage(msg, sk_ValueType),
	ErrorMessage(msg[Messages::sk_LabelRoot][SGXRAClientMessage::sk_LabelRoot])
{
}

SGXRAClientErrMsg::~SGXRAClientErrMsg()
{
}

std::string SGXRAClientErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & SGXRAClientErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	//parent[SGXRAClientMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = GetErrorStr();

	return parent;
}

SGXRASPErrMsg::SGXRASPErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXRASPMessage(senderID),
	ErrorMessage(errStr)
{
}

SGXRASPErrMsg::SGXRASPErrMsg(const Json::Value & msg) :
	SGXRASPMessage(msg, sk_ValueType),
	ErrorMessage(msg[Messages::sk_LabelRoot][SGXRASPMessage::sk_LabelRoot])
{
}

SGXRASPErrMsg::~SGXRASPErrMsg()
{
}

std::string SGXRASPErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & SGXRASPErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = GetErrorStr();

	return parent;
}
