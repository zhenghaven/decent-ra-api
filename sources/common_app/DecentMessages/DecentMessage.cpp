#include "DecentMessage.h"

#include <json/json.h>

#include "../MessageException.h"

constexpr char DecentMessage::sk_LabelRoot[];
constexpr char DecentMessage::sk_LabelType[];
constexpr char DecentMessage::sk_ValueCat[];

std::string DecentMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(sk_LabelRoot) && MsgRootContent[sk_LabelRoot].isObject() &&
		MsgRootContent[sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[sk_LabelRoot][sk_LabelType].isString()
		)
	{
		return MsgRootContent[sk_LabelRoot][sk_LabelType].asString();
	}
	throw MessageParseException();
}

DecentMessage::DecentMessage(const std::string & senderID) :
	Messages(senderID)
{
}

DecentMessage::DecentMessage(const Json::Value & msg, const char* expectedType) :
	Messages(msg, sk_ValueCat)
{
	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
	{
		throw MessageParseException();
	}
}

DecentMessage::~DecentMessage()
{
}

std::string DecentMessage::GetMessageCategoryStr() const
{
	return sk_ValueCat;
}

Json::Value & DecentMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[sk_LabelRoot] = Json::objectValue;
	parent[sk_LabelRoot][sk_LabelType] = GetMessageTypeStr();

	return parent[sk_LabelRoot];
}

DecentErrMsg::DecentErrMsg(const std::string & senderID, const std::string & errStr) :
	DecentMessage(senderID),
	ErrorMessage(errStr)
{
}

DecentErrMsg::DecentErrMsg(const Json::Value & msg) :
	DecentMessage(msg, sk_ValueType),
	ErrorMessage(msg[Messages::sk_LabelRoot][DecentMessage::sk_LabelRoot])
{
}

DecentErrMsg::~DecentErrMsg()
{
}

std::string DecentErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = GetErrorStr();

	return parent;
}

constexpr char DecentRAHandshake::sk_ValueType[];

DecentRAHandshake::DecentRAHandshake(const std::string & senderID) :
	DecentMessage(senderID)
{
}

DecentRAHandshake::DecentRAHandshake(const Json::Value & msg) :
	DecentMessage(msg, sk_ValueType)
{
}

DecentRAHandshake::~DecentRAHandshake()
{
}

std::string DecentRAHandshake::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentRAHandshake::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;

	return parent;
}

constexpr char DecentRAHandshakeAck::sk_LabelSelfReport[];
constexpr char DecentRAHandshakeAck::sk_ValueType[];

std::string DecentRAHandshakeAck::ParseSelfRAReport(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelSelfReport) && DecentRoot[sk_LabelSelfReport].isString())
	{
		return DecentRoot[sk_LabelSelfReport].asString();
	}
	throw MessageParseException();
}

DecentRAHandshakeAck::DecentRAHandshakeAck(const std::string & senderID, const std::string& selfRAReport) :
	DecentMessage(senderID),
	m_selfRAReport(selfRAReport)
{
}

DecentRAHandshakeAck::DecentRAHandshakeAck(const Json::Value & msg) :
	DecentMessage(msg, sk_ValueType),
	m_selfRAReport(ParseSelfRAReport(msg[Messages::sk_LabelRoot][DecentMessage::sk_LabelRoot]))
{
}

DecentRAHandshakeAck::~DecentRAHandshakeAck()
{
}

std::string DecentRAHandshakeAck::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const std::string & DecentRAHandshakeAck::GetSelfRAReport() const
{
	return m_selfRAReport;
}

Json::Value & DecentRAHandshakeAck::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelSelfReport] = m_selfRAReport;

	return parent;
}

constexpr char DecentProtocolKeyReq::sk_ValueType[];

DecentProtocolKeyReq::DecentProtocolKeyReq(const std::string & senderID) :
	DecentMessage(senderID)
{
}

DecentProtocolKeyReq::DecentProtocolKeyReq(const Json::Value & msg) :
	DecentMessage(msg, sk_ValueType)
{
}

DecentProtocolKeyReq::~DecentProtocolKeyReq()
{
}

std::string DecentProtocolKeyReq::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentProtocolKeyReq::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;

	return parent;
}

constexpr char DecentTrustedMessage::sk_LabelTrustedMsg[];
constexpr char DecentTrustedMessage::sk_ValueType[];

std::string DecentTrustedMessage::ParseTrustedMsg(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelTrustedMsg) && DecentRoot[sk_LabelTrustedMsg].isString())
	{
		return DecentRoot[sk_LabelTrustedMsg].asString();
	}
	throw MessageParseException();
}

DecentTrustedMessage::DecentTrustedMessage(const std::string & senderID, const std::string & trustedMsg) :
	DecentMessage(senderID),
	m_trustedMsg(trustedMsg)
{
}

DecentTrustedMessage::DecentTrustedMessage(const Json::Value & msg) :
	DecentMessage(msg, sk_ValueType),
	m_trustedMsg(ParseTrustedMsg(msg[Messages::sk_LabelRoot][DecentMessage::sk_LabelRoot]))
{
}

DecentTrustedMessage::~DecentTrustedMessage()
{
}

std::string DecentTrustedMessage::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const std::string & DecentTrustedMessage::GetTrustedMsg() const
{
	return m_trustedMsg;
}

Json::Value & DecentTrustedMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelTrustedMsg] = m_trustedMsg;

	return parent;
}
