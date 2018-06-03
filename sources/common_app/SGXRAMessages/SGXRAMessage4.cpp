#include "SGXRAMessage4.h"

#include <sgx_key_exchange.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../../common/sgx_ra_msg4.h"
#include "../../common/CryptoTools.h"

SGXRAMessage4::SGXRAMessage4(const std::string& senderID, const sgx_ra_msg4_t& msg4Data, const sgx_ec256_signature_t& signature) :
	SGXRAMessage(senderID),
	m_msg4Data(new sgx_ra_msg4_t(msg4Data)),
	m_signature(new sgx_ec256_signature_t(signature))
{
	m_isValid = true;
}

SGXRAMessage4::SGXRAMessage4(Json::Value& msg) :
	SGXRAMessage(msg),
	m_msg4Data(new sgx_ra_msg4_t),
	m_signature(new sgx_ec256_signature_t)
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
		&& root["MsgType"].asString() == SGXRAMessage::GetMessageTypeStr(GetType())
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("msg4Data")
		&& root["Untrusted"].isMember("msg4Sign"))
	{
		//Get message 4 normal data.
		std::string msg4B64 = root["Untrusted"]["msg4Data"].asString();
		std::vector<uint8_t> buffer1;
		cppcodec::base64_rfc4648::decode(buffer1, msg4B64);
		std::memcpy(m_msg4Data, buffer1.data(), sizeof(sgx_ra_msg4_t));

		std::string signB64Str = root["Untrusted"]["msg4Sign"].asString();
		DeserializeSignature(signB64Str, *m_signature);
		
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessage4::~SGXRAMessage4()
{
	delete m_msg4Data;
	delete m_signature;
}

std::string SGXRAMessage4::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
}

SGXRAMessage::Type SGXRAMessage4::GetType() const
{
	return SGXRAMessage::Type::MSG4_RESP;
}

bool SGXRAMessage4::IsResp() const
{
	return true;
}

const sgx_ra_msg4_t& SGXRAMessage4::GetMsg4Data() const
{
	return *m_msg4Data;
}

const sgx_ec256_signature_t & SGXRAMessage4::GetMsg4Signature() const
{
	return *m_signature;
}

Json::Value & SGXRAMessage4::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	std::string msg4B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const char*>(m_msg4Data), sizeof(sgx_ra_msg4_t));
	jsonUntrusted["msg4Data"] = msg4B64Str;

	jsonUntrusted["msg4Sign"] = SerializeSignature(*m_signature);

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
