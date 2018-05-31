#pragma once

#include "SGXRAMessage.h"

#include <sgx_key_exchange.h>

#include <json/json.h>

//Forward Declarations:
//struct _ra_msg1_t;
//typedef _ra_msg1_t sgx_ra_msg1_t;

class SGXRAMessage1 : public SGXRAMessage
{
public:
	SGXRAMessage1() = delete;
	SGXRAMessage1(sgx_ra_msg1_t& msg1Data);
	SGXRAMessage1(Json::Value& msg);
	~SGXRAMessage1();

	virtual std::string ToJsonString() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg1_t& GetMsg1Data() const;

private:
	sgx_ra_msg1_t m_msg1Data;
};
