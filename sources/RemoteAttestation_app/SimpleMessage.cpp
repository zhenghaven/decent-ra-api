#include "SimpleMessage.h"

#include <cstring>

#include "../common/CryptoTools.h"

SimpleMessage::SimpleMessage(const std::string & senderID, const uint64_t& secret, const sgx_aes_gcm_128bit_tag_t& inSecretMac) :
	EnclaveMessages(senderID),
	m_secret(secret)
{
	std::memcpy(&m_secretMac, &inSecretMac, sizeof(sgx_aes_gcm_128bit_tag_t));
	m_isValid = true;
}

SimpleMessage::SimpleMessage(Json::Value & msg) :
	EnclaveMessages(msg)
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
		&& root["MsgType"].isString()
		&& root["MsgType"].asString() == "simple_msg"
		&& root.isMember("Trusted")
		&& root["Trusted"].isMember("Secret")
		&& root["Trusted"].isMember("SecretMac")
		&& root["Trusted"]["Secret"].isString()
		&& root["Trusted"]["SecretMac"].isString())
	{
		DeserializeStruct(root["Trusted"]["Secret"].asString(), m_secret);
		DeserializeStruct(root["Trusted"]["SecretMac"].asString(), m_secretMac);
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

SimpleMessage::~SimpleMessage()
{
}

std::string SimpleMessage::GetMessgaeSubTypeStr() const
{
	return "simple_msg";
}

const uint64_t & SimpleMessage::GetSecret() const
{
	return m_secret;
}

const sgx_aes_gcm_128bit_tag_t & SimpleMessage::GetSecretMac() const
{
	return m_secretMac;
}

std::string SimpleMessage::ToJsonString() const
{
	Json::Value jsonRoot;

	GetJsonMsg(jsonRoot);

	return jsonRoot.toStyledString();
}

Json::Value & SimpleMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = EnclaveMessages::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonTrusted;

	jsonTrusted["Secret"] = SerializeStruct(m_secret);
	jsonTrusted["SecretMac"] = SerializeStruct(m_secretMac);

	child["MsgType"] = "simple_msg";
	child["Untrusted"] = Json::nullValue;
	child["Trusted"] = jsonTrusted;

	return child;
}
