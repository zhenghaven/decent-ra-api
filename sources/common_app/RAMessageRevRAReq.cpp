#include "RAMessageRevRAReq.h"

RAMessageRevRAReq::RAMessageRevRAReq(const std::string & senderID) :
	RAMessages(senderID)
{
}

RAMessageRevRAReq::RAMessageRevRAReq(Json::Value & msg) :
	RAMessages(msg)
{
	if (!IsValid())
	{
		return;
	}

	if (!msg.isMember("child")
		|| !msg["child"].isObject())
	{
		m_isValid = false;
		return;
	}

	Json::Value& root = msg["child"];

	if (root.isMember("MsgType")
		&& root["MsgType"].asString() == "ReverseRARequest")
	{
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

RAMessageRevRAReq::~RAMessageRevRAReq()
{
}

std::string RAMessageRevRAReq::ToJsonString() const
{
	Json::Value jsonRoot;

	GetJsonMsg(jsonRoot);

	return jsonRoot.toStyledString();
}

std::string RAMessageRevRAReq::GetMessgaeSubTypeStr() const
{
	return "ReverseRARequest";
}

Json::Value & RAMessageRevRAReq::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = RAMessages::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted = Json::objectValue;

	child["MsgType"] = "ReverseRARequest";
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
