#include "SGXRAMessage1.h"

#include <json/json.h>

#include "../../MessageException.h"

#include "../../../common/DataCoding.h"

sgx_ra_msg1_t SGXRAMessage1::ParseMsg1Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage1::LABEL_DATA) && SGXRASPRoot[SGXRAMessage1::LABEL_DATA].isString())
	{
		sgx_ra_msg1_t res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage1::LABEL_DATA].asString());
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
	SGXRASPMessage(msg, VALUE_TYPE),
	m_msg1Data(ParseMsg1Data(msg[Messages::LABEL_ROOT][SGXRASPMessage::LABEL_ROOT]))
{
}

SGXRAMessage1::~SGXRAMessage1()
{
}

std::string SGXRAMessage1::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const sgx_ra_msg1_t& SGXRAMessage1::GetMsg1Data() const
{
	return m_msg1Data;
}

Json::Value & SGXRAMessage1::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_DATA] = SerializeStruct(m_msg1Data);

	return parent;
}
