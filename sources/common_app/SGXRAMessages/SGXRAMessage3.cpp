#include "SGXRAMessage3.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <sgx_key_exchange.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../IAS/IASUtil.h"
//#include "../../common/CryptoTools.h"

SGXRAMessage3::SGXRAMessage3(const std::string& senderID, sgx_ra_msg3_t& msg3Data, const std::vector<uint8_t>& quoteData) :
	SGXRAMessage(senderID),
	m_msg3Data(nullptr)
{
	m_msg3Data = reinterpret_cast<sgx_ra_msg3_t*>(std::malloc(sizeof(sgx_ra_msg3_t) + quoteData.size()));

	std::memcpy(m_msg3Data, &msg3Data, sizeof(sgx_ra_msg3_t));

	std::memcpy(m_msg3Data->quote, quoteData.data(), quoteData.size());

	m_isQuoteValid = (quoteData.size() > 0);

	m_isValid = m_isQuoteValid;
}

SGXRAMessage3::SGXRAMessage3(Json::Value& msg) :
	SGXRAMessage(msg),
	m_msg3Data(nullptr)
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
		&& root["Untrusted"].isMember("msg3Data")
		&& root["Untrusted"].isMember("quoteData"))
	{
		std::string quoteB64 = root["Untrusted"]["quoteData"].asString();
		std::vector<uint8_t> buffer1;
		cppcodec::base64_rfc4648::decode(buffer1, quoteB64);

		m_msg3Data = reinterpret_cast<sgx_ra_msg3_t*>(std::malloc(sizeof(sgx_ra_msg3_t) + buffer1.size()));

		//Get message 3 normal data.
		std::string msg3B64Str = root["Untrusted"]["msg3Data"].asString();
		std::vector<uint8_t> buffer2(sizeof(sgx_ra_msg3_t), 0);
		cppcodec::base64_rfc4648::decode(buffer2, msg3B64Str);
		memcpy(m_msg3Data, buffer2.data(), sizeof(sgx_ra_msg3_t));

		std::memcpy(m_msg3Data->quote, buffer1.data(), buffer1.size());
		
		//Check if valid.
		m_isQuoteValid = (buffer1.size() > 0);
		m_isValid = m_isQuoteValid;
	}
	else
	{
		m_msg3Data = reinterpret_cast<sgx_ra_msg3_t*>(std::malloc(sizeof(sgx_ra_msg3_t)));
		m_isValid = false;
	}
}

SGXRAMessage3::~SGXRAMessage3()
{
	std::free(m_msg3Data);
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

const sgx_ra_msg3_t& SGXRAMessage3::GetMsg3Data() const
{
	return *m_msg3Data;
}

bool SGXRAMessage3::IsQuoteValid() const
{
	return m_isQuoteValid;
}

Json::Value & SGXRAMessage3::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	std::string msg3B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(m_msg3Data), sizeof(sgx_ra_msg3_t));
	jsonUntrusted["msg3Data"] = msg3B64Str;
	sgx_quote_t* quotePtr = reinterpret_cast<sgx_quote_t*>(m_msg3Data->quote);
	std::string quoteB64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(quotePtr), sizeof(sgx_quote_t) + quotePtr->signature_len);
	jsonUntrusted["quoteData"] = quoteB64Str;

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
