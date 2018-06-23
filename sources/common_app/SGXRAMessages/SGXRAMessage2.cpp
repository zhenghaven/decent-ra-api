#include "SGXRAMessage2.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <sgx_key_exchange.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../IAS/IASUtil.h"
//#include "../../common/CryptoTools.h"

SGXRAMessage2::SGXRAMessage2(const std::string& senderID, sgx_ra_msg2_t& msg2Data, const sgx_epid_group_id_t& gid) :
	SGXRAMessage(senderID),
	m_msg2Data(nullptr),
	m_rl()
{
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

	m_isRLValid = GetRevocationList(gid, m_rl);
	std::vector<uint8_t> buffer;
	cppcodec::base64_rfc4648::decode(buffer, m_rl);

	if (m_isRLValid)
	{
		m_msg2Data = reinterpret_cast<sgx_ra_msg2_t*>(std::malloc(sizeof(sgx_ra_msg2_t) + buffer.size()));
		std::memcpy(m_msg2Data, &msg2Data, sizeof(sgx_ra_msg2_t));
		m_msg2Data->sig_rl_size = static_cast<uint32_t>(buffer.size());

		std::memcpy(m_msg2Data->sig_rl, buffer.data(), buffer.size());
	}
	else
	{
		m_msg2Data = reinterpret_cast<sgx_ra_msg2_t*>(std::malloc(sizeof(sgx_ra_msg2_t)));
		std::memcpy(m_msg2Data, &msg2Data, sizeof(sgx_ra_msg2_t));
		m_msg2Data->sig_rl_size = 0;
	}

	m_isValid = m_isRLValid;
}

SGXRAMessage2::SGXRAMessage2(Json::Value& msg) :
	SGXRAMessage(msg),
	m_msg2Data(nullptr)
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
		&& root["Untrusted"].isMember("msg2Data")
		&& root["Untrusted"].isMember("rl"))
	{
		//Get data in revocation list.
		m_rl = root["Untrusted"]["rl"].asString();
		std::vector<uint8_t> buffer1;
		cppcodec::base64_rfc4648::decode(buffer1, m_rl);

		m_msg2Data = reinterpret_cast<sgx_ra_msg2_t*>(std::malloc(sizeof(sgx_ra_msg2_t) + buffer1.size()));

		//Get message 2 normal data.
		std::string msg2B64Str = root["Untrusted"]["msg2Data"].asString();
		std::vector<uint8_t> buffer2(sizeof(sgx_ra_msg2_t), 0);
		cppcodec::base64_rfc4648::decode(buffer2, msg2B64Str);
		memcpy(m_msg2Data, buffer2.data(), sizeof(sgx_ra_msg2_t));
		
		//Check if valid.
		m_isRLValid = (m_msg2Data->sig_rl_size == buffer1.size());
		//Copy the revocation list data anyway.
		std::memcpy(m_msg2Data->sig_rl, buffer1.data(), buffer1.size());

		m_isValid = m_isRLValid;
	}
	else
	{
		m_msg2Data = reinterpret_cast<sgx_ra_msg2_t*>(std::malloc(sizeof(sgx_ra_msg2_t)));
		m_isValid = false;
	}

	//std::cout << "Signature: " << std::endl;
	//size_t xSize = sizeof(m_msg2Data->sign_gb_ga.x) / sizeof(uint32_t);
	//size_t ySize = sizeof(m_msg2Data->sign_gb_ga.y) / sizeof(uint32_t);
	//for (int i = 0; i < xSize; ++i)
	//{
	//	std::cout << m_msg2Data->sign_gb_ga.x[i] << " ";
	//}
	//std::cout << std::endl;
	//for (int i = 0; i < ySize; ++i)
	//{
	//	std::cout << m_msg2Data->sign_gb_ga.y[i] << " ";
	//}
	//std::cout << std::endl;
}

SGXRAMessage2::~SGXRAMessage2()
{
	std::free(m_msg2Data);
}

std::string SGXRAMessage2::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
}

SGXRAMessage::Type SGXRAMessage2::GetType() const
{
	return SGXRAMessage::Type::MSG2_RESP;
}

bool SGXRAMessage2::IsResp() const
{
	return true;
}

const sgx_ra_msg2_t& SGXRAMessage2::GetMsg2Data() const
{
	return *m_msg2Data;
}

bool SGXRAMessage2::IsRLValid() const
{
	return m_isRLValid;
}

Json::Value & SGXRAMessage2::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	std::string msg2B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(m_msg2Data), sizeof(sgx_ra_msg2_t));

	jsonUntrusted["msg2Data"] = msg2B64Str;
	jsonUntrusted["rl"] = m_rl;

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
