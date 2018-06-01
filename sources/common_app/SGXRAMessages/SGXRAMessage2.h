#pragma once

#include "SGXRAMessage.h"

#include <sgx_key_exchange.h>

#include <json/json.h>

//Forward Declarations:
//struct _ra_msg1_t;
//typedef _ra_msg1_t sgx_ra_msg1_t;

class SGXRAMessage2 : public SGXRAMessage
{
public:
	SGXRAMessage2() = delete;
	SGXRAMessage2(sgx_ra_msg2_t& msg2Data);
	SGXRAMessage2(Json::Value& msg);
	~SGXRAMessage2();

	virtual std::string ToJsonString() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg2_t& GetMsg2Data() const;

private:
	sgx_ra_msg2_t m_msg2Data;
};
