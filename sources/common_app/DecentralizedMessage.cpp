#include "DecentralizedMessage.h"

#include <json/json.h>

#include "MessageException.h"

constexpr char DecentralizedMessage::sk_LabelRoot[];
constexpr char DecentralizedMessage::sk_LabelType[];
constexpr char DecentralizedMessage::sk_ValueCat[];

std::string DecentralizedMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(DecentralizedMessage::sk_LabelRoot) && MsgRootContent[DecentralizedMessage::sk_LabelRoot].isObject() &&
		MsgRootContent[DecentralizedMessage::sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[DecentralizedMessage::sk_LabelRoot][sk_LabelType].isString()
		)
	{
		return MsgRootContent[DecentralizedMessage::sk_LabelRoot][sk_LabelType].asString();
	}
	throw MessageParseException();
}

DecentralizedMessage::DecentralizedMessage(const std::string & senderID) :
	Messages(senderID)
{
}

DecentralizedMessage::DecentralizedMessage(const Json::Value & msg, const char* expectedType) :
	Messages(msg, sk_ValueCat)
{
	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
	{
		throw MessageParseException();
	}
}

DecentralizedMessage::~DecentralizedMessage()
{
}

std::string DecentralizedMessage::GetMessageCategoryStr() const
{
	return DecentralizedMessage::sk_ValueCat;
}

Json::Value & DecentralizedMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[DecentralizedMessage::sk_LabelRoot] = Json::objectValue;
	parent[DecentralizedMessage::sk_LabelRoot][DecentralizedMessage::sk_LabelType] = GetMessageTypeStr();

	return parent[DecentralizedMessage::sk_LabelRoot];
}

constexpr char DecentralizedErrMsg::sk_LabelErrMsg[];
constexpr char DecentralizedErrMsg::sk_ValueType[];

std::string DecentralizedErrMsg::ParseErrorMsg(const Json::Value & DecentralizedRoot)
{
	if (DecentralizedRoot.isMember(DecentralizedErrMsg::sk_LabelErrMsg) && DecentralizedRoot[DecentralizedErrMsg::sk_LabelErrMsg].isString())
	{
		return DecentralizedRoot[DecentralizedErrMsg::sk_LabelErrMsg].asString();
	}
	throw MessageParseException();
}

DecentralizedErrMsg::DecentralizedErrMsg(const std::string & senderID, const std::string & errStr) :
	DecentralizedMessage(senderID),
	m_errStr(errStr)
{
}

DecentralizedErrMsg::DecentralizedErrMsg(const Json::Value & msg) :
	DecentralizedMessage(msg, sk_ValueType),
	m_errStr(ParseErrorMsg(msg[Messages::sk_LabelRoot][DecentralizedMessage::sk_LabelRoot]))
{
}

DecentralizedErrMsg::~DecentralizedErrMsg()
{
}

std::string DecentralizedErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const std::string & DecentralizedErrMsg::GetErrStr() const
{
	return m_errStr;
}

Json::Value & DecentralizedErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = m_errStr;

	return parent;
}

constexpr char DecentralizedRAHandshake::sk_ValueType[];

DecentralizedRAHandshake::DecentralizedRAHandshake(const std::string & senderID) :
	DecentralizedMessage(senderID)
{
}

DecentralizedRAHandshake::DecentralizedRAHandshake(const Json::Value & msg) :
	DecentralizedMessage(msg, sk_ValueType)
{
}

DecentralizedRAHandshake::~DecentralizedRAHandshake()
{
}

std::string DecentralizedRAHandshake::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentralizedRAHandshake::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;

	return parent;
}

constexpr char DecentralizedRAHandshakeAck::sk_ValueType[];

DecentralizedRAHandshakeAck::DecentralizedRAHandshakeAck(const std::string & senderID) :
	DecentralizedMessage(senderID)
{
}

DecentralizedRAHandshakeAck::DecentralizedRAHandshakeAck(const Json::Value & msg) :
	DecentralizedMessage(msg, sk_ValueType)
{
}

DecentralizedRAHandshakeAck::~DecentralizedRAHandshakeAck()
{
}

std::string DecentralizedRAHandshakeAck::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentralizedRAHandshakeAck::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;

	return parent;
}

constexpr char DecentralizedReverseReq::sk_ValueType[];

DecentralizedReverseReq::DecentralizedReverseReq(const std::string & senderID) :
	DecentralizedMessage(senderID)
{
}

DecentralizedReverseReq::DecentralizedReverseReq(const Json::Value & msg) :
	DecentralizedMessage(msg, sk_ValueType)
{
}

DecentralizedReverseReq::~DecentralizedReverseReq()
{
}

std::string DecentralizedReverseReq::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentralizedReverseReq::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;

	return parent;
}
