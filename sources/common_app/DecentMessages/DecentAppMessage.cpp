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

constexpr char DecentAppTrustedMessage::sk_LabelTrustedMsg[];
constexpr char DecentAppTrustedMessage::sk_LabelAppAttach[];
constexpr char DecentAppTrustedMessage::sk_ValueType[];

std::string DecentAppTrustedMessage::ParseTrustedMsg(const Json::Value & DecentAppRoot)
{
	if (DecentAppRoot.isMember(sk_LabelTrustedMsg) && DecentAppRoot[sk_LabelTrustedMsg].isString())
	{
		return DecentAppRoot[sk_LabelTrustedMsg].asString();
	}
	throw MessageParseException();
}

std::string DecentAppTrustedMessage::ParseAppAttach(const Json::Value & DecentAppRoot)
{
	if (DecentAppRoot.isMember(sk_LabelAppAttach) && DecentAppRoot[sk_LabelAppAttach].isString())
	{
		return DecentAppRoot[sk_LabelAppAttach].asString();
	}
	throw MessageParseException();
}

DecentAppTrustedMessage::DecentAppTrustedMessage(const Json::Value & msg) :
	DecentAppMessage(msg, sk_ValueType),
	m_trustedMsg(ParseTrustedMsg(msg[Messages::sk_LabelRoot][DecentAppMessage::sk_LabelRoot])),
	m_appAttach(ParseAppAttach(msg[Messages::sk_LabelRoot][DecentAppMessage::sk_LabelRoot]))
{
}

Json::Value & DecentAppTrustedMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentAppMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelTrustedMsg] = m_trustedMsg;
	parent[sk_LabelAppAttach] = m_appAttach;

	return parent;
}
