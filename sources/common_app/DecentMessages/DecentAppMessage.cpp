#include "DecentAppMessage.h"

#include <json/json.h>

#include "../MessageException.h"

constexpr char DecentAppMessage::sk_LabelRoot[];
constexpr char DecentAppMessage::sk_LabelType[];
constexpr char DecentAppMessage::sk_ValueCat[];

std::string DecentAppMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(sk_LabelRoot) && MsgRootContent[sk_LabelRoot].isObject() &&
		MsgRootContent[sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[sk_LabelRoot][sk_LabelType].isString()
		)
	{
		return MsgRootContent[sk_LabelRoot][sk_LabelType].asString();
	}
	throw MessageParseException();
}

DecentAppMessage::DecentAppMessage(const Json::Value & msg, const char * expectedType) :
	Messages(msg, sk_ValueCat)
{
	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
	{
		throw MessageParseException();
	}
}

Json::Value & DecentAppMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[sk_LabelRoot] = Json::objectValue;
	parent[sk_LabelRoot][sk_LabelType] = GetMessageTypeStr();

	return parent[sk_LabelRoot];
}

DecentAppErrMsg::DecentAppErrMsg(const Json::Value & msg) :
	DecentAppMessage(msg, sk_ValueType),
	ErrorMessage(msg[Messages::sk_LabelRoot][DecentAppMessage::sk_LabelRoot])
{
}

Json::Value & DecentAppErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentAppMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = GetErrorStr();

	return parent;
}

constexpr char DecentAppHandshake::sk_ValueType[];

DecentAppHandshake::DecentAppHandshake(const std::string & senderID) :
	DecentAppMessage(senderID)
{
}

DecentAppHandshake::DecentAppHandshake(const Json::Value & msg) :
	DecentAppMessage(msg, sk_ValueType)
{
}

DecentAppHandshake::~DecentAppHandshake()
{
}

std::string DecentAppHandshake::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & DecentAppHandshake::GetJsonMsg(Json::Value & outJson) const
{
	return DecentAppMessage::GetJsonMsg(outJson);
}

constexpr char DecentAppHandshakeAck::sk_LabelSelfReport[];
constexpr char DecentAppHandshakeAck::sk_ValueType[];

std::string DecentAppHandshakeAck::ParseSelfRAReport(const Json::Value & DecentAppRoot)
{
	if (DecentAppRoot.isMember(sk_LabelSelfReport) && DecentAppRoot[sk_LabelSelfReport].isString())
	{
		return DecentAppRoot[sk_LabelSelfReport].asString();
	}
	throw MessageParseException();
}

DecentAppHandshakeAck::DecentAppHandshakeAck(const std::string & senderID, const std::string & selfRAReport) :
	DecentAppMessage(senderID),
	m_selfRAReport(selfRAReport)
{
}

DecentAppHandshakeAck::DecentAppHandshakeAck(const Json::Value & msg) :
	DecentAppMessage(msg, sk_ValueType),
	m_selfRAReport(ParseSelfRAReport(msg[Messages::sk_LabelRoot][DecentAppMessage::sk_LabelRoot]))
{
}

DecentAppHandshakeAck::~DecentAppHandshakeAck()
{
}

std::string DecentAppHandshakeAck::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const std::string & DecentAppHandshakeAck::GetSelfRAReport() const
{
	return m_selfRAReport;
}

Json::Value & DecentAppHandshakeAck::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentAppMessage::GetJsonMsg(outJson);

	parent[sk_LabelSelfReport] = m_selfRAReport;

	return parent;
}
