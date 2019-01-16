//#include "DecentMessage.h"
//
//#include <json/json.h>
//
//#include "../MessageException.h"
//
//constexpr char DecentMessage::sk_LabelRoot[];
//constexpr char DecentMessage::sk_LabelType[];
//constexpr char DecentMessage::sk_ValueCat[];
//
//std::string DecentMessage::ParseType(const Json::Value & MsgRootContent)
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
//DecentMessage::DecentMessage(const Json::Value & msg, const char* expectedType) :
//	Messages(msg, sk_ValueCat)
//{
//	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
//	{
//		throw MessageParseException();
//	}
//}
//
//Json::Value & DecentMessage::GetJsonMsg(Json::Value & outJson) const
//{
//	Json::Value& parent = Messages::GetJsonMsg(outJson);
//
//	parent[sk_LabelRoot] = Json::objectValue;
//	parent[sk_LabelRoot][sk_LabelType] = GetMessageTypeStr();
//
//	return parent[sk_LabelRoot];
//}
//
//DecentErrMsg::DecentErrMsg(const Json::Value & msg) :
//	DecentMessage(msg, sk_ValueType),
//	ErrorMessage(msg[Messages::sk_LabelRoot][DecentMessage::sk_LabelRoot])
//{
//}
//
//Json::Value & DecentErrMsg::GetJsonMsg(Json::Value & outJson) const
//{
//	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);
//
//	//parent[DecentMessage::sk_LabelType] = sk_ValueType;
//	parent[sk_LabelErrMsg] = GetErrorStr();
//
//	return parent;
//}
