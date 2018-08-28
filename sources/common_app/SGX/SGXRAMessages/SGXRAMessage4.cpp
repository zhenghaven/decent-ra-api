#include "SGXRAMessage4.h"

#include <json/json.h>

#include <sgx_key_exchange.h>

#include "../../MessageException.h"

#include "../../../common/DataCoding.h"
#include "../../../common/SGX/sgx_ra_msg4.h"

sgx_ra_msg4_t SGXRAMessage4::ParseMsg4Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage4::sk_LabelData) && SGXRASPRoot[SGXRAMessage4::sk_LabelData].isString())
	{
		sgx_ra_msg4_t res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage4::sk_LabelData].asString());
		return res;
	}
	throw MessageParseException();
}

sgx_ec256_signature_t SGXRAMessage4::ParseMsg4Sign(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage4::sk_LabelSign) && SGXRASPRoot[SGXRAMessage4::sk_LabelSign].isString())
	{
		sgx_ec256_signature_t res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage4::sk_LabelSign].asString());
		return res;
	}
	throw MessageParseException();
}

SGXRAMessage4::SGXRAMessage4(const std::string& senderID, const sgx_ra_msg4_t& msg4Data, const sgx_ec256_signature_t& signature) :
	SGXRAClientMessage(senderID),
	m_msg4Data(msg4Data),
	m_signature(signature)
{
}

SGXRAMessage4::SGXRAMessage4(const Json::Value& msg) :
	SGXRAClientMessage(msg, sk_ValueType),
	m_msg4Data(ParseMsg4Data(msg[Messages::sk_LabelRoot][SGXRAClientMessage::sk_LabelRoot])),
	m_signature(ParseMsg4Sign(msg[Messages::sk_LabelRoot][SGXRAClientMessage::sk_LabelRoot]))
{
}

SGXRAMessage4::~SGXRAMessage4()
{
}

std::string SGXRAMessage4::GetMessageTypeStr() const
{
	return sk_ValueType;
}

const sgx_ra_msg4_t& SGXRAMessage4::GetMsg4Data() const
{
	return m_msg4Data;
}

const sgx_ec256_signature_t & SGXRAMessage4::GetMsg4Signature() const
{
	return m_signature;
}

Json::Value & SGXRAMessage4::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	//parent[SGXRAClientMessage::sk_LabelType] = sk_ValueType;
	parent[sk_LabelData] = SerializeStruct(m_msg4Data);
	parent[sk_LabelSign] = SerializeStruct(m_signature);

	return parent;
}
