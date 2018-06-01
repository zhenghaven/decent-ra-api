#include "SGXRAMessage2.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <cppcodec/base64_rfc4648.hpp>

//#include "../../common/CryptoTools.h"

SGXRAMessage2::SGXRAMessage2(sgx_ra_msg2_t& msg2Data) :
	m_msg2Data(msg2Data)
{
	m_isValid = true;

	//std::cout << "Signature: " << std::endl;
	//size_t xSize = sizeof(msg2Data.sign_gb_ga.x) / sizeof(uint32_t);
	//size_t ySize = sizeof(msg2Data.sign_gb_ga.y) / sizeof(uint32_t);
	//for (int i = 0; i < xSize; ++i)
	//{
	//	std::cout << msg2Data.sign_gb_ga.x[i] << " ";
	//}
	//std::cout << std::endl;
	//for (int i = 0; i < ySize; ++i)
	//{
	//	std::cout << msg2Data.sign_gb_ga.y[i] << " ";
	//}
	//std::cout << std::endl;

	//std::cout << "g_b: " << std::endl << SerializePubKey(msg2Data.g_b) << std::endl;
}

SGXRAMessage2::SGXRAMessage2(Json::Value& msg)
{
	if (msg.isMember("MsgType")
		&& msg["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& msg.isMember("Untrusted")
		&& msg["Untrusted"].isMember("msg2Data"))
	{
		std::string msg2B64Str = msg["Untrusted"]["msg2Data"].asString();
		std::vector<uint8_t> buffer(sizeof(sgx_ra_msg2_t), 0);
		cppcodec::base64_rfc4648::decode(buffer, msg2B64Str);
		memcpy(&m_msg2Data, buffer.data(), sizeof(sgx_ra_msg2_t));
		m_isValid = true;
	}
	else
	{
		m_isValid = false;
	}

	//std::cout << "Signature: " << std::endl;
	//size_t xSize = sizeof(m_msg2Data.sign_gb_ga.x) / sizeof(uint32_t);
	//size_t ySize = sizeof(m_msg2Data.sign_gb_ga.y) / sizeof(uint32_t);
	//for (int i = 0; i < xSize; ++i)
	//{
	//	std::cout << m_msg2Data.sign_gb_ga.x[i] << " ";
	//}
	//std::cout << std::endl;
	//for (int i = 0; i < ySize; ++i)
	//{
	//	std::cout << m_msg2Data.sign_gb_ga.y[i] << " ";
	//}
	//std::cout << std::endl;
}

SGXRAMessage2::~SGXRAMessage2()
{
}

std::string SGXRAMessage2::ToJsonString() const
{
	Json::Value jsonRoot;
	Json::Value jsonUntrusted;

	std::string msg1B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(&m_msg2Data), sizeof(sgx_ra_msg2_t));
	jsonUntrusted["msg2Data"] = msg1B64Str;

	jsonRoot["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	jsonRoot["Untrusted"] = jsonUntrusted;
	jsonRoot["Trusted"] = Json::nullValue;

	return jsonRoot.toStyledString();
}

SGXRAMessage::Type SGXRAMessage2::GetType() const
{
	return SGXRAMessage::Type::MSG2_RESP;
}

bool SGXRAMessage2::IsResp() const
{
	return false;
}

const sgx_ra_msg2_t& SGXRAMessage2::GetMsg2Data() const
{
	return m_msg2Data;
}
