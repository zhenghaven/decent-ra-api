#include "SGXRAMessage4.h"

#include <json/json.h>

#include <sgx_key_exchange.h>

#include "../../MessageException.h"

#include "../../../common/DataCoding.h"
#include "../../../common/SGX/sgx_ra_msg4.h"

sgx_ra_msg4_t SGXRAMessage4::ParseMsg4Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage4::LABEL_DATA) && SGXRASPRoot[SGXRAMessage4::LABEL_DATA].isString())
	{
		sgx_ra_msg4_t res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage4::LABEL_DATA].asString());
		return res;
	}
	throw MessageParseException();
}

sgx_ec256_signature_t SGXRAMessage4::ParseMsg4Sign(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage4::LABEL_SIGN) && SGXRASPRoot[SGXRAMessage4::LABEL_SIGN].isString())
	{
		sgx_ec256_signature_t res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage4::LABEL_SIGN].asString());
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
	SGXRAClientMessage(msg),
	m_msg4Data(ParseMsg4Data(msg[Messages::LABEL_ROOT][SGXRAClientMessage::LABEL_ROOT])),
	m_signature(ParseMsg4Sign(msg[Messages::LABEL_ROOT][SGXRAClientMessage::LABEL_ROOT]))
{
}

SGXRAMessage4::~SGXRAMessage4()
{
}

std::string SGXRAMessage4::GetMessageTypeStr() const
{
	return VALUE_TYPE;
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

	parent[SGXRAClientMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_DATA] = SerializeStruct(m_msg4Data);
	parent[LABEL_SIGN] = SerializeStruct(m_signature);

	return parent;
}
