#pragma once

#include "SGXRAMessage.h"

#include <vector>
#include <cstdint>

#include <json/json.h>

//Forward Declarations:
struct _ra_msg2_t;
typedef _ra_msg2_t sgx_ra_msg2_t;

class SGXRAMessage2 : public SGXRAMessage
{
public:
	SGXRAMessage2() = delete;
	SGXRAMessage2(const std::string& senderID, const std::vector<uint8_t>& msg2Data);
	SGXRAMessage2(Json::Value& msg);
	~SGXRAMessage2();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg2_t& GetMsg2() const;

	const std::vector<uint8_t>& GetMsg2Data() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	std::vector<uint8_t> m_msg2Data;
};
