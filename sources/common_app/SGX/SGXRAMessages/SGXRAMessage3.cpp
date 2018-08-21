#include "SGXRAMessage3.h"

#include <json/json.h>

#include <sgx_key_exchange.h>

#include "../../MessageException.h"
#include "../../../common/DataCoding.h"

std::vector<uint8_t> SGXRAMessage3::ParseMsg3Data(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRAMessage3::LABEL_DATA) && SGXRASPRoot[SGXRAMessage3::LABEL_DATA].isString())
	{
		std::vector<uint8_t> res;
		DeserializeStruct(res, SGXRASPRoot[SGXRAMessage3::LABEL_DATA].asString());

		const sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<const sgx_ra_msg3_t*>(res.data());
		const sgx_quote_t& quotePtr = *reinterpret_cast<const sgx_quote_t*>(msg3Ref.quote);

		if (res.size() == (sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t) + quotePtr.signature_len))
		{
			return res;
		}
	}
	throw MessageParseException();
}

SGXRAMessage3::SGXRAMessage3(const std::string& senderID, const std::vector<uint8_t>& msg3Data) :
	SGXRASPMessage(senderID),
	m_msg3Data(msg3Data)
{
	const sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
	const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(msg3Ref.quote);
	if (m_msg3Data.size() != (sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t) + quotePtr->signature_len))
	{
		throw MessageInvalidException();
	}
}

SGXRAMessage3::SGXRAMessage3(const Json::Value& msg) :
	SGXRASPMessage(msg),
	m_msg3Data(ParseMsg3Data(msg[Messages::LABEL_ROOT][SGXRASPMessage::LABEL_ROOT]))
{
}

SGXRAMessage3::~SGXRAMessage3()
{
}

std::string SGXRAMessage3::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const sgx_ra_msg3_t & SGXRAMessage3::GetMsg3() const
{
	return *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
}

const std::vector<uint8_t>& SGXRAMessage3::GetMsg3Data() const
{
	return m_msg3Data;
}

const uint32_t SGXRAMessage3::GetMsg3DataSize() const
{
	return static_cast<uint32_t>(m_msg3Data.size());
}

std::string SGXRAMessage3::GetQuoteBase64() const
{
	const sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<const sgx_ra_msg3_t*>(m_msg3Data.data());
	const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(msg3Ref.quote);
	return SerializeStruct(quotePtr, sizeof(sgx_quote_t) + quotePtr->signature_len);
}

Json::Value & SGXRAMessage3::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_DATA] = SerializeStruct(m_msg3Data.data(), m_msg3Data.size());

	return parent;
}
