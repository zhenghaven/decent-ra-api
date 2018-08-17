#include "SGXRAMessage1.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <cppcodec/base64_rfc4648.hpp>

//#include "../../common/DataCoding.h"

SGXRAMessage1::SGXRAMessage1(const std::string& senderID, sgx_ra_msg1_t& msg1Data) :
	SGXRAMessage(senderID),
	m_msg1Data(msg1Data)
{
	m_isValid = true;

	//std::cout << "g_a: " << std::endl << SerializePubKey(msg1Data.g_a) << std::endl;
}

SGXRAMessage1::SGXRAMessage1(Json::Value& msg) :
	SGXRAMessage(msg),
	m_msg1Data({ 0 })
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
		&& root["MsgType"].asString().compare(SGXRAMessage::GetMessageTypeStr(GetType())) == 0
		&& root.isMember("Untrusted")
		&& root["Untrusted"].isMember("msg1Data"))
	{
		std::string msg1B64Str = root["Untrusted"]["msg1Data"].asString();
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

std::string SGXRAMessage1::GetMessgaeSubTypeStr() const
{
	return SGXRAMessage::GetMessageTypeStr(GetType());
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

Json::Value & SGXRAMessage1::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	std::string msg1B64Str = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(&m_msg1Data), sizeof(sgx_ra_msg1_t));
	jsonUntrusted["msg1Data"] = msg1B64Str;

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
