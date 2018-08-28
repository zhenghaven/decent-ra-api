#include "SGXRAMessage2.h"

#include <json/json.h>

#include <sgx_key_exchange.h>

#include "../../MessageException.h"
#include "../../../common/DataCoding.h"

std::vector<uint8_t> SGXRAMessage2::ParseMsg2Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage2::LABEL_DATA) && SGXRASPRoot[SGXRAMessage2::LABEL_DATA].isString())
	{
		std::vector<uint8_t> res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage2::LABEL_DATA].asString());

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
	SGXRAClientMessage(msg, VALUE_TYPE),
	m_msg2Data(ParseMsg2Data(msg[Messages::LABEL_ROOT][SGXRAClientMessage::LABEL_ROOT]))
{
}

SGXRAMessage2::~SGXRAMessage2()
{
}

std::string SGXRAMessage2::GetMessageTypeStr() const
{
	return VALUE_TYPE;
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

	//parent[SGXRAClientMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_DATA] = SerializeStruct(m_msg2Data.data(), m_msg2Data.size());

	return parent;
}
