#include "SGXRAMessage2.h"

#include <json/json.h>

#include <sgx_key_exchange.h>

#include "../../MessageException.h"
#include "../../../common/DataCoding.h"

std::vector<uint8_t> SGXRAMessage2::ParseMsg2Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage2::sk_LabelData) && SGXRASPRoot[SGXRAMessage2::sk_LabelData].isString())
	{
		std::vector<uint8_t> res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage2::sk_LabelData].asString());

		sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(res.data());

		if ((msg2Ref.sig_rl_size + sizeof(sgx_ra_msg2_t) == res.size()))
		{
			return res;
		}
	}
	throw MessageParseException();
}

SGXRAMessage2::SGXRAMessage2(const std::string& senderID, const std::vector<uint8_t>& msg2Data) :
	SGXRAClientMessage(senderID),
	m_msg2Data(msg2Data)
{
}

SGXRAMessage2::SGXRAMessage2(const Json::Value& msg) :
	SGXRAClientMessage(msg, sk_ValueType),
	m_msg2Data(ParseMsg2Data(msg[Messages::sk_LabelRoot][SGXRAClientMessage::sk_LabelRoot]))
{
}

SGXRAMessage2::~SGXRAMessage2()
{
}

std::string SGXRAMessage2::GetMessageTypeStr() const
{
	return sk_ValueType;
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
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	//parent[SGXRAClientMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelData] = SerializeStruct(m_msg2Data.data(), m_msg2Data.size());

	return parent;
}
