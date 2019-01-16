#include "DecentAppMessage.h"

#include <json/json.h>

#include "../MessageException.h"

//constexpr char DecentAppMessage::sk_LabelRoot[];
//constexpr char DecentAppMessage::sk_LabelType[];
//constexpr char DecentAppMessage::sk_ValueCat[];
//
//std::string DecentAppMessage::ParseType(const Json::Value & MsgRootContent)
//{
//	if (MsgRootContent.isMember(sk_LabelRoot) && MsgRootContent[sk_LabelRoot].isObject() &&
//		MsgRootContent[sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[sk_LabelRoot][sk_LabelType].isString()
//		)
//	{
//		return MsgRootContent[sk_LabelRoot][sk_LabelType].asString();
//	}
//	throw MessageParseException();
//}
//
//DecentAppMessage::DecentAppMessage(const Json::Value & msg, const char * expectedType) :
//	Messages(msg, sk_ValueCat)
//{
//	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
//	{
//		throw MessageParseException();
//	}
//}
//
//Json::Value & DecentAppMessage::GetJsonMsg(Json::Value & outJson) const
//{
//	Json::Value& parent = Messages::GetJsonMsg(outJson);
//
//	parent[sk_LabelRoot] = Json::objectValue;
//	parent[sk_LabelRoot][sk_LabelType] = GetMessageTypeStr();
//
//	return parent[sk_LabelRoot];
//}
//
//DecentAppErrMsg::DecentAppErrMsg(const Json::Value & msg) :
//	DecentAppMessage(msg, sk_ValueType),
//	ErrorMessage(msg[Messages::sk_LabelRoot][DecentAppMessage::sk_LabelRoot])
//{
//}
//
//Json::Value & DecentAppErrMsg::GetJsonMsg(Json::Value & outJson) const
//{
//	Json::Value& parent = DecentAppMessage::GetJsonMsg(outJson);
//
//	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
//	parent[sk_LabelErrMsg] = GetErrorStr();
//
//	return parent;
//}

constexpr char DecentLoadWhiteList::sk_LabelRoot[];
constexpr char DecentLoadWhiteList::sk_ValueCat[];
constexpr char DecentLoadWhiteList::sk_LabelKey[];
constexpr char DecentLoadWhiteList::sk_LabelWhiteList[];

std::string DecentLoadWhiteList::ParseKey(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelKey) && DecentRoot[sk_LabelKey].isString())
	{
		return DecentRoot[sk_LabelKey].asString();
	}
	throw MessageParseException();
}

std::string DecentLoadWhiteList::ParseWhiteList(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelWhiteList) && DecentRoot[sk_LabelWhiteList].isString())
	{
		return DecentRoot[sk_LabelWhiteList].asString();
	}
	throw MessageParseException();
}

DecentLoadWhiteList::DecentLoadWhiteList(const Json::Value & msg) :
	Messages(msg, sk_ValueCat),
	m_key(ParseKey(msg[Messages::sk_LabelRoot])),
	m_whiteList(ParseWhiteList(msg[Messages::sk_LabelRoot]))
{
}

Json::Value & DecentLoadWhiteList::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[sk_LabelKey] = m_key;
	parent[sk_LabelWhiteList] = m_whiteList;

	return parent;
}

constexpr char DecentRequestAppCert::sk_LabelRoot[];
constexpr char DecentRequestAppCert::sk_ValueCat[];
constexpr char DecentRequestAppCert::sk_LabelKey[];

std::string DecentRequestAppCert::ParseKey(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelKey) && DecentRoot[sk_LabelKey].isString())
	{
		return DecentRoot[sk_LabelKey].asString();
	}
	throw MessageParseException();
}

DecentRequestAppCert::DecentRequestAppCert(const Json::Value & msg) :
	Messages(msg, sk_ValueCat),
	m_key(ParseKey(msg[Messages::sk_LabelRoot]))
{
}

Json::Value & DecentRequestAppCert::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[sk_LabelKey] = m_key;

	return parent;
}

//constexpr char DecentAppHandshake::sk_ValueType[];
//
//constexpr char DecentAppHandshakeAck::sk_LabelSelfReport[];
//constexpr char DecentAppHandshakeAck::sk_ValueType[];
//
//std::string DecentAppHandshakeAck::ParseSelfRAReport(const Json::Value & DecentAppRoot)
//{
//	if (DecentAppRoot.isMember(sk_LabelSelfReport) && DecentAppRoot[sk_LabelSelfReport].isString())
//	{
//		return DecentAppRoot[sk_LabelSelfReport].asString();
//	}
//	throw MessageParseException();
//}
//
//DecentAppHandshakeAck::DecentAppHandshakeAck(const Json::Value & msg) :
//	DecentAppMessage(msg, sk_ValueType),
//	m_selfRAReport(ParseSelfRAReport(msg[Messages::sk_LabelRoot][DecentAppMessage::sk_LabelRoot]))
//{
//}
//
//Json::Value & DecentAppHandshakeAck::GetJsonMsg(Json::Value & outJson) const
//{
//	Json::Value& parent = DecentAppMessage::GetJsonMsg(outJson);
//
//	parent[sk_LabelSelfReport] = m_selfRAReport;
//
//	return parent;
//}
