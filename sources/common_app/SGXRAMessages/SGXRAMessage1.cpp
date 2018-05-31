#include "SGXRAMessage1.h"

#include <memory>
#include <climits>

#include <cppcodec/base64_rfc4648.hpp>

SGXRAMessage1::SGXRAMessage1(sgx_ra_msg1_t& msg1Data) :
	m_msg1Data(msg1Data)
{
	m_isValid = true;
}

SGXRAMessage1::SGXRAMessage1(Json::Value& msg)
{
	if (msg.isMember("MsgType")
		&& msg["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& msg.isMember("Untrusted")
		&& msg["Untrusted"].isMember("msg1Data"))
	{
		std::string msg1B64Str = msg["Untrusted"]["msg1Data"].asString();
		cppcodec::base64_rfc4648::decode(reinterpret_cast<uint8_t*>(&m_msg1Data), sizeof(sgx_ra_msg1_t), msg1B64Str);
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessage1::~SGXRAMessage1()
{
}

std::string SGXRAMessage1::ToJsonString() const
{
	Json::Value jsonRoot;
	Json::Value jsonUntrusted;

	std::string msg1B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(&m_msg1Data), sizeof(sgx_ra_msg1_t));
	jsonUntrusted["msg1Data"] = msg1B64Str;

	jsonRoot["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	jsonRoot["Untrusted"] = jsonUntrusted;
	jsonRoot["Trusted"] = Json::nullValue;

	return jsonRoot.toStyledString();
}

SGXRAMessage::Type SGXRAMessage1::GetType() const
{
	return SGXRAMessage::Type::MSG1_SEND;
}

bool SGXRAMessage1::IsResp() const
{
	return false;
}

const sgx_ra_msg1_t& SGXRAMessage1::GetMsg1Data() const
{
	return m_msg1Data;
}
