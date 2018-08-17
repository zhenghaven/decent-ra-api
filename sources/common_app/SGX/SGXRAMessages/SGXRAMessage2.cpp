#include "SGXRAMessage2.h"

#include <memory>
#include <climits>
//#include <iostream>

#include <sgx_key_exchange.h>

#include "../IAS/IASUtil.h"
#include "../../../common/DataCoding.h"

SGXRAMessage2::SGXRAMessage2(const std::string& senderID, const std::vector<uint8_t>& msg2Data) :
	SGXRAMessage(senderID),
	m_msg2Data(msg2Data)
{
	m_isValid = true;
}

SGXRAMessage2::SGXRAMessage2(Json::Value& msg) :
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
		&& root["Untrusted"].isMember("msg2Data"))
	{
		DeserializeStruct(m_msg2Data, root["Untrusted"]["msg2Data"].asString());
		sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(m_msg2Data.data());
		
		//Check if valid.
		m_isValid = (msg2Ref.sig_rl_size + sizeof(sgx_ra_msg2_t) == m_msg2Data.size());
	}
	else
	{
		m_isValid = false;
	}
}

SGXRAMessage2::~SGXRAMessage2()
{
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

const sgx_ra_msg2_t & SGXRAMessage2::GetMsg2() const
{
	return *reinterpret_cast<const sgx_ra_msg2_t*>(m_msg2Data.data());
}

const std::vector<uint8_t>& SGXRAMessage2::GetMsg2Data() const
{
	return m_msg2Data;
}

Json::Value & SGXRAMessage2::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAMessage::GetJsonMsg(outJson);

	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];

	Json::Value jsonUntrusted;

	jsonUntrusted["msg2Data"] = SerializeStruct(m_msg2Data.data(), m_msg2Data.size());

	child["MsgType"] = SGXRAMessage::GetMessageTypeStr(GetType());
	child["Untrusted"] = jsonUntrusted;
	child["Trusted"] = Json::nullValue;

	return child;
}
