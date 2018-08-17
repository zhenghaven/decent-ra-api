#include "DecentMessageMsg0.h"

#include "../../common/DataCoding.h"

DecentMessageMsg0::DecentMessageMsg0(const std::string & senderID, const sgx_ec256_public_t& inSignKey, const sgx_ec256_signature_t& inSignSign, const sgx_ec256_public_t& inEncrKey, const sgx_ec256_signature_t& inEncrSign) :
	DecentMessage(senderID),
	m_signKey(inSignKey),
	m_signSign(inSignSign),
	m_encrKey(inEncrKey),
	m_encrSign(inEncrSign)
{
	m_isValid = true;
}

DecentMessageMsg0::DecentMessageMsg0(Json::Value & msg) :
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
		&& root["Untrusted"].isMember("SignKey")
		&& root["Untrusted"].isMember("SignSign")
		&& root["Untrusted"].isMember("EncrKey")
		&& root["Untrusted"].isMember("EncrSign")
		&& root["Untrusted"]["SignKey"].isString()
		&& root["Untrusted"]["SignSign"].isString()
		&& root["Untrusted"]["EncrKey"].isString()
		&& root["Untrusted"]["EncrSign"].isString())
	{
		DeserializeStruct(m_signKey, root["Untrusted"]["SignKey"].asString());
		DeserializeStruct(m_signSign, root["Untrusted"]["SignSign"].asString());
		DeserializeStruct(m_encrKey, root["Untrusted"]["EncrKey"].asString());
		DeserializeStruct(m_encrSign, root["Untrusted"]["EncrSign"].asString());
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

DecentMessageMsg0::~DecentMessageMsg0()
{
}

DecentMessage::Type DecentMessageMsg0::GetType() const
{
	return DecentMessage::Type::DECENT_MSG0;
}

std::string DecentMessageMsg0::GetMessgaeSubTypeStr() const
{
	return DecentMessage::GetMessageTypeStr(GetType());
}

const sgx_ec256_public_t & DecentMessageMsg0::GetSignKey() const
{
	return m_signKey;
}

const sgx_ec256_signature_t & DecentMessageMsg0::GetSignSign() const
{
	return m_signSign;
}

const sgx_ec256_public_t & DecentMessageMsg0::GetEncrKey() const
{
	return m_encrKey;
}

const sgx_ec256_signature_t & DecentMessageMsg0::GetEncrSign() const
{
	return m_encrSign;
}

Json::Value & DecentMessageMsg0::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["SignKey"] = SerializeStruct(m_signKey);
	jsonUntrusted["SignSign"] = SerializeStruct(m_signSign);
	jsonUntrusted["EncrKey"] = SerializeStruct(m_encrKey);
	jsonUntrusted["EncrSign"] = SerializeStruct(m_encrSign);

	child["MsgType"] = DecentMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
