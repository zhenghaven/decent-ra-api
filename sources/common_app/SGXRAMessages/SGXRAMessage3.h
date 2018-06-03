#pragma once

#include "SGXRAMessage.h"

#include <json/json.h>

//Forward Declarations:
struct _ra_msg3_t;
typedef _ra_msg3_t sgx_ra_msg3_t;
//struct _quote_t;
//typedef _quote_t sgx_quote_t;
//typedef uint8_t sgx_epid_group_id_t[4];

class SGXRAMessage3 : public SGXRAMessage
{
public:
	SGXRAMessage3() = delete;
	SGXRAMessage3(const std::string& senderID, sgx_ra_msg3_t& msg3Data, const std::vector<uint8_t>& quoteData);
	SGXRAMessage3(Json::Value& msg);
	~SGXRAMessage3();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg3_t& GetMsg3Data() const;

	const uint32_t GetMsg3DataSize() const;

	bool IsQuoteValid() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	sgx_ra_msg3_t* m_msg3Data;

	bool m_isQuoteValid;
};
