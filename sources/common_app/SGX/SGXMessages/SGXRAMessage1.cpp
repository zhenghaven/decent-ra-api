#include "SGXRAMessage1.h"

#include <json/json.h>

#include "../../MessageException.h"

#include "../../../common/DataCoding.h"

constexpr char SGXRAMessage1::sk_LabelData[];
constexpr char SGXRAMessage1::sk_ValueType[];

sgx_ra_msg1_t SGXRAMessage1::ParseMsg1Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage1::sk_LabelData) && SGXRASPRoot[SGXRAMessage1::sk_LabelData].isString())
	{
		sgx_ra_msg1_t res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage1::sk_LabelData].asString());
		return res;
	}
	throw MessageParseException();
}

SGXRAMessage1::SGXRAMessage1(const std::string& senderID, const sgx_ra_msg1_t& msg1Data) :
	SGXRASPMessage(senderID),
	m_msg1Data(msg1Data)
{
}

SGXRAMessage1::SGXRAMessage1(const Json::Value& msg) :
	SGXRASPMessage(msg, sk_ValueType),
	m_msg1Data(ParseMsg1Data(msg[Messages::sk_LabelRoot][SGXRASPMessage::sk_LabelRoot]))
{
}

SGXRAMessage1::~SGXRAMessage1()
{
}

std::string SGXRAMessage1::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const sgx_ra_msg1_t& SGXRAMessage1::GetMsg1Data() const
{
	return m_msg1Data;
}

Json::Value & SGXRAMessage1::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelData] = SerializeStruct(m_msg1Data);

	return parent;
}
