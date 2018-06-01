#include "SGXRAMessage3.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <sgx_key_exchange.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../IAS/IASUtil.h"
//#include "../../common/CryptoTools.h"

SGXRAMessage3::SGXRAMessage3(sgx_ra_msg3_t& msg3Data, const std::vector<uint8_t>& quoteData) :
	m_msg3Data(nullptr)
{
	m_msg3Data = reinterpret_cast<sgx_ra_msg3_t*>(std::malloc(sizeof(sgx_ra_msg3_t) + quoteData.size()));

	std::memcpy(m_msg3Data, &msg3Data, sizeof(sgx_ra_msg3_t));

	std::memcpy(m_msg3Data->quote, quoteData.data(), quoteData.size());

	m_isQuoteValid = (quoteData.size() > 0);

	m_isValid = m_isQuoteValid;
}

SGXRAMessage3::SGXRAMessage3(Json::Value& msg) :
	m_msg3Data(nullptr)
{
	if (msg.isMember("MsgType")
		&& msg["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& msg.isMember("Untrusted")
		&& msg["Untrusted"].isMember("msg3Data")
		&& msg["Untrusted"].isMember("quoteData"))
	{
		std::string quoteB64 = msg["Untrusted"]["quoteData"].asString();
		std::vector<uint8_t> buffer1;
		cppcodec::base64_rfc4648::decode(buffer1, quoteB64);

		m_msg3Data = reinterpret_cast<sgx_ra_msg3_t*>(std::malloc(sizeof(sgx_ra_msg3_t) + buffer1.size()));

		//Get message 3 normal data.
		std::string msg3B64Str = msg["Untrusted"]["msg3Data"].asString();
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

std::string SGXRAMessage3::ToJsonString() const
{
	Json::Value jsonRoot;
	Json::Value jsonUntrusted;

	std::string msg3B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(m_msg3Data), sizeof(sgx_ra_msg3_t));
	jsonUntrusted["msg3Data"] = msg3B64Str;
	sgx_quote_t* quotePtr = reinterpret_cast<sgx_quote_t*>(m_msg3Data->quote);
	std::string quoteB64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(quotePtr), sizeof(sgx_quote_t) + quotePtr->signature_len);
	jsonUntrusted["quoteData"] = quoteB64Str;

	jsonRoot["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	jsonRoot["Untrusted"] = jsonUntrusted;
	jsonRoot["Trusted"] = Json::nullValue;

	return jsonRoot.toStyledString();
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
