#include "DecentMessageKeyReq.h"

#include "../../common/DataCoding.h"

DecentMessageKeyReq::DecentMessageKeyReq(const std::string & senderID, DecentNodeMode mode, sgx_ec256_public_t& signKey, sgx_ec256_public_t& encrKey) :
	DecentMessage(senderID),
	m_mode(mode),
	m_signKey(signKey),
	m_encrKey(encrKey)
{
	m_isValid = true;
}

DecentMessageKeyReq::DecentMessageKeyReq(Json::Value & msg) :
	DecentMessage(msg)
{
	if (!IsValid())
	{
		return;
	}

	Json::Value& parent = msg["child"];

	if (!parent.isMember("child")
		|| !parent["child"].isObject())
	{
		m_isValid = false;
		return;
	}

	Json::Value& root = parent["child"];

	if (root.isMember("MsgType")
		&& root["MsgType"].isString()
		&& root["MsgType"].asString() == DecentMessage::GetMessageTypeStr(GetType())
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("Mode")
		&& root["Untrusted"].isMember("SignKey")
		&& root["Untrusted"].isMember("EncrKey")
		&& root["Untrusted"]["SignKey"].isString()
		&& root["Untrusted"]["EncrKey"].isString()
		&& root["Untrusted"]["Mode"].isInt())
	{
		m_mode = static_cast<DecentNodeMode>(root["Untrusted"]["Mode"].asInt());
		DeserializePubKey(root["Untrusted"]["SignKey"].asString(), m_signKey);
		DeserializePubKey(root["Untrusted"]["EncrKey"].asString(), m_encrKey);
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

DecentMessageKeyReq::~DecentMessageKeyReq()
{
}

DecentMessage::Type DecentMessageKeyReq::GetType() const
{
	return DecentMessage::Type::DECENT_KEY_REQ;
}

std::string DecentMessageKeyReq::GetMessgaeSubTypeStr() const
{
	return DecentMessage::GetMessageTypeStr(GetType());
}

Json::Value & DecentMessageKeyReq::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["Mode"] = static_cast<int>(m_mode);
	jsonUntrusted["SignKey"] = SerializePubKey(m_signKey);
	jsonUntrusted["EncrKey"] = SerializePubKey(m_encrKey);

	child["MsgType"] = DecentMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}

DecentNodeMode DecentMessageKeyReq::GetMode() const
{
	return m_mode;
}

const sgx_ec256_public_t & DecentMessageKeyReq::GetSignKey() const
{
	return m_signKey;
}

const sgx_ec256_public_t & DecentMessageKeyReq::GetEncrKey() const
{
	return m_encrKey;
}
