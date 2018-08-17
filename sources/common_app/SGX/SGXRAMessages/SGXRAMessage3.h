#pragma once

#include "SGXRAMessage.h"

#include <json/json.h>

//Forward Declarations:
struct _ra_msg3_t;
typedef _ra_msg3_t sgx_ra_msg3_t;

class SGXRAMessage3 : public SGXRAMessage
{
public:
	SGXRAMessage3() = delete;
	SGXRAMessage3(const std::string& senderID, const std::vector<uint8_t>& msg3Data);
	SGXRAMessage3(Json::Value& msg);
	~SGXRAMessage3();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg3_t& GetMsg3() const;

	const std::vector<uint8_t>& GetMsg3Data() const;

	const uint32_t GetMsg3DataSize() const;

	std::string GetQuoteBase64() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	std::vector<uint8_t> m_msg3Data;
};
