#include "SGXRAMessage3.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <sgx_key_exchange.h>

#include "../IAS/IASUtil.h"
#include "../../../common/DataCoding.h"

SGXRAMessage3::SGXRAMessage3(const std::string& senderID, const std::vector<uint8_t>& msg3Data) :
	SGXRAMessage(senderID),
	m_msg3Data(msg3Data)
{
	const sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
	const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(msg3Ref.quote);
	m_isValid = m_msg3Data.size() == (sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t) + quotePtr->signature_len);
}

SGXRAMessage3::SGXRAMessage3(Json::Value& msg) :
	SGXRAMessage(msg)
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
		&& root["Untrusted"].isMember("msg3Data"))
	{
		DeserializeStruct(m_msg3Data, root["Untrusted"]["msg3Data"].asString());
		const sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
		const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(msg3Ref.quote);
		m_isValid = m_msg3Data.size() == (sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t) + quotePtr->signature_len);
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessage3::~SGXRAMessage3()
{
}

std::string SGXRAMessage3::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
}

SGXRAMessage::Type SGXRAMessage3::GetType() const
{
	return SGXRAMessage::Type::MSG3_SEND;
}

bool SGXRAMessage3::IsResp() const
{
	return false;
}

const sgx_ra_msg3_t & SGXRAMessage3::GetMsg3() const
{
	return *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
}

const std::vector<uint8_t>& SGXRAMessage3::GetMsg3Data() const
{
	return m_msg3Data;
}

const uint32_t SGXRAMessage3::GetMsg3DataSize() const
{
	return static_cast<uint32_t>(m_msg3Data.size());
}

std::string SGXRAMessage3::GetQuoteBase64() const
{
	const sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
	const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(msg3Ref.quote);
	return SerializeStruct(quotePtr, sizeof(sgx_quote_t) + quotePtr->signature_len);
}

Json::Value & SGXRAMessage3::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["msg3Data"] = SerializeStruct(m_msg3Data.data(), m_msg3Data.size());

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
