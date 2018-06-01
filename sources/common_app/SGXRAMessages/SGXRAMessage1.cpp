#include "SGXRAMessage1.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <cppcodec/base64_rfc4648.hpp>

//#include "../../common/CryptoTools.h"

SGXRAMessage1::SGXRAMessage1(sgx_ra_msg1_t& msg1Data) :
	m_msg1Data(msg1Data)
{
	m_isValid = true;

	//std::cout << "g_a: " << std::endl << SerializePubKey(msg1Data.g_a) << std::endl;
}

SGXRAMessage1::SGXRAMessage1(Json::Value& msg) :
	m_msg1Data({ 0 })
{
	if (msg.isMember("MsgType")
		&& msg["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& msg.isMember("Untrusted")
		&& msg["Untrusted"].isMember("msg1Data"))
	{
		std::string msg1B64Str = msg["Untrusted"]["msg1Data"].asString();
		std::vector<uint8_t> buffer(sizeof(sgx_ra_msg1_t), 0);
		cppcodec::base64_rfc4648::decode(buffer, msg1B64Str);
		memcpy(&m_msg1Data, buffer.data(), sizeof(sgx_ra_msg1_t));
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
