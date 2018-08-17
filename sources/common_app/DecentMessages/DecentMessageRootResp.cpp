#include "DecentMessageRootResp.h"

#include <cstring>

#include "../../common/DataCoding.h"

DecentMessageRootResp::DecentMessageRootResp(const std::string& senderID,
	const sgx_ec256_private_t& inPriSignKey, const sgx_aes_gcm_128bit_tag_t& inPriSignKeyMac,
	const sgx_ec256_public_t& inPubSignKey, const sgx_aes_gcm_128bit_tag_t& inPubSignKeyMac,
	const sgx_ec256_private_t& inPriEncrKey, const sgx_aes_gcm_128bit_tag_t& inPriEncrKeyMac,
	const sgx_ec256_public_t& inPubEncrKey, const sgx_aes_gcm_128bit_tag_t& inPubEncrKeyMac) :
	DecentMessage(senderID),
	m_priSignKey(inPriSignKey),
	m_pubSignKey(inPubSignKey),
	m_priEncrKey(inPriEncrKey),
	m_pubEncrKey(inPubEncrKey)
{
	std::memcpy(&m_priSignKeyMac, &inPriSignKeyMac, sizeof(sgx_aes_gcm_128bit_tag_t));
	std::memcpy(&m_pubSignKeyMac, &inPubSignKeyMac, sizeof(sgx_aes_gcm_128bit_tag_t));
	std::memcpy(&m_priEncrKeyMac, &inPriEncrKeyMac, sizeof(sgx_aes_gcm_128bit_tag_t));
	std::memcpy(&m_pubEncrKeyMac, &inPubEncrKeyMac, sizeof(sgx_aes_gcm_128bit_tag_t));

	m_isValid = true;
}

DecentMessageRootResp::DecentMessageRootResp(Json::Value & msg) :
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
		&& root["Untrusted"].isMember("PriSignKey")
		&& root["Untrusted"].isMember("PriSignKeyMac")
		&& root["Untrusted"].isMember("PubSignKey")
		&& root["Untrusted"].isMember("PubSignKeyMac")
		&& root["Untrusted"].isMember("PriEncrKey")
		&& root["Untrusted"].isMember("PriEncrKeyMac")
		&& root["Untrusted"].isMember("PubEncrKey")
		&& root["Untrusted"].isMember("PubEncrKeyMac")
		&& root["Untrusted"]["PriSignKey"].isString()
		&& root["Untrusted"]["PriSignKeyMac"].isString()
		&& root["Untrusted"]["PubSignKey"].isString()
		&& root["Untrusted"]["PubSignKeyMac"].isString()
		&& root["Untrusted"]["PriEncrKey"].isString()
		&& root["Untrusted"]["PriEncrKeyMac"].isString()
		&& root["Untrusted"]["PubEncrKey"].isString()
		&& root["Untrusted"]["PubEncrKeyMac"].isString()
		)
	{
		DeserializeStruct(m_priSignKey, root["Untrusted"]["PriSignKey"].asString());
		DeserializeStruct(m_priSignKeyMac, root["Untrusted"]["PriSignKeyMac"].asString());
		DeserializeStruct(m_pubSignKey, root["Untrusted"]["PubSignKey"].asString());
		DeserializeStruct(m_pubSignKeyMac,root["Untrusted"]["PubSignKeyMac"].asString());

		DeserializeStruct(m_priEncrKey,root["Untrusted"]["PriEncrKey"].asString());
		DeserializeStruct(m_priEncrKeyMac,root["Untrusted"]["PriEncrKeyMac"].asString());
		DeserializeStruct(m_pubEncrKey,root["Untrusted"]["PubEncrKey"].asString());
		DeserializeStruct(m_pubEncrKeyMac,root["Untrusted"]["PubEncrKeyMac"].asString());
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

DecentMessageRootResp::~DecentMessageRootResp()
{
}

DecentMessage::Type DecentMessageRootResp::GetType() const
{
	return DecentMessage::Type::ROOT_NODE_RESP;
}

std::string DecentMessageRootResp::GetMessgaeSubTypeStr() const
{
	return DecentMessage::GetMessageTypeStr(GetType());
}

const sgx_ec256_private_t & DecentMessageRootResp::GetPriSignKey() const
{
	return m_priSignKey;
}

const sgx_aes_gcm_128bit_tag_t & DecentMessageRootResp::GetPriSignKeyMac() const
{
	return m_priSignKeyMac;
}

const sgx_ec256_public_t & DecentMessageRootResp::GetPubSignKey() const
{
	return m_pubSignKey;
}

const sgx_aes_gcm_128bit_tag_t & DecentMessageRootResp::GetPubSignKeyMac() const
{
	return m_pubSignKeyMac;
}

const sgx_ec256_private_t & DecentMessageRootResp::GetPriEncrKey() const
{
	return m_priEncrKey;
}

const sgx_aes_gcm_128bit_tag_t & DecentMessageRootResp::GetPriEncrKeyMac() const
{
	return m_priEncrKeyMac;
}

const sgx_ec256_public_t & DecentMessageRootResp::GetPubEncrKey() const
{
	return m_pubEncrKey;
}

const sgx_aes_gcm_128bit_tag_t & DecentMessageRootResp::GetPubEncrKeyMac() const
{
	return m_pubEncrKeyMac;
}

Json::Value & DecentMessageRootResp::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["PriSignKey"] = SerializeStruct(m_priSignKey);
	jsonUntrusted["PriSignKeyMac"] = SerializeStruct(m_priSignKeyMac);
	jsonUntrusted["PubSignKey"] = SerializeStruct(m_pubSignKey);
	jsonUntrusted["PubSignKeyMac"] = SerializeStruct(m_pubSignKeyMac);

	jsonUntrusted["PriEncrKey"] = SerializeStruct(m_priEncrKey);
	jsonUntrusted["PriEncrKeyMac"] = SerializeStruct(m_priEncrKeyMac);
	jsonUntrusted["PubEncrKey"] = SerializeStruct(m_pubEncrKey);
	jsonUntrusted["PubEncrKeyMac"] = SerializeStruct(m_pubEncrKeyMac);

	child["MsgType"] = DecentMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
