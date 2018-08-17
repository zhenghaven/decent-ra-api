#include "DecentMessageApplResp.h"

#include <cstring>

#include "../../common/DataCoding.h"

DecentMessageApplResp::DecentMessageApplResp(const std::string & senderID, const sgx_ec256_signature_t& signSign, const sgx_aes_gcm_128bit_tag_t& signMac, const sgx_ec256_signature_t& encrSign, const sgx_aes_gcm_128bit_tag_t& encrMac) :
	DecentMessage(senderID),
	m_signSign(signSign),
	m_encrSign(encrSign)
{
	std::memcpy(&m_signMac, &signMac, sizeof(sgx_aes_gcm_128bit_tag_t));
	std::memcpy(&m_encrMac, &encrMac, sizeof(sgx_aes_gcm_128bit_tag_t));

	m_isValid = true;
}

DecentMessageApplResp::DecentMessageApplResp(Json::Value & msg) :
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
		&& root["Untrusted"].isMember("SignSign")
		&& root["Untrusted"].isMember("EncrSign")
		&& root["Untrusted"].isMember("SignMac")
		&& root["Untrusted"].isMember("EncrMac")
		&& root["Untrusted"]["SignSign"].isString()
		&& root["Untrusted"]["EncrSign"].isString()
		&& root["Untrusted"]["SignMac"].isString()
		&& root["Untrusted"]["EncrMac"].isString())
	{
		DeserializeStruct(m_signSign, root["Untrusted"]["SignSign"].asString());
		DeserializeStruct(m_encrSign, root["Untrusted"]["EncrSign"].asString());
		DeserializeStruct(m_signMac, root["Untrusted"]["SignMac"].asString());
		DeserializeStruct(m_encrMac, root["Untrusted"]["EncrMac"].asString());
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

DecentMessageApplResp::~DecentMessageApplResp()
{
}

DecentMessage::Type DecentMessageApplResp::GetType() const
{
	return DecentMessage::Type::APPL_NODE_RESP;
}

std::string DecentMessageApplResp::GetMessgaeSubTypeStr() const
{
	return DecentMessage::GetMessageTypeStr(GetType());
}

const sgx_ec256_signature_t & DecentMessageApplResp::GetSignSign() const
{
	return m_signSign;
}

const sgx_ec256_signature_t & DecentMessageApplResp::GetEncrSign() const
{
	return m_encrSign;
}

const sgx_aes_gcm_128bit_tag_t & DecentMessageApplResp::GetSignMac() const
{
	return m_signMac;
}

const sgx_aes_gcm_128bit_tag_t & DecentMessageApplResp::GetEncrMac() const
{
	return m_encrMac;
}

Json::Value & DecentMessageApplResp::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["SignSign"] = SerializeStruct(m_signSign);
	jsonUntrusted["EncrSign"] = SerializeStruct(m_encrSign);
	jsonUntrusted["SignMac"] = SerializeStruct(m_signMac);
	jsonUntrusted["EncrMac"] = SerializeStruct(m_encrMac);

	child["MsgType"] = DecentMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
