#pragma once

#include "SGXRAMessage.h"

#include <json/json.h>

//Forward Declarations:
struct _ra_msg2_t;
typedef _ra_msg2_t sgx_ra_msg2_t;
typedef uint8_t sgx_epid_group_id_t[4];

class SGXRAMessage2 : public SGXRAMessage
{
public:
	SGXRAMessage2() = delete;
	SGXRAMessage2(const std::string& senderID, sgx_ra_msg2_t& msg2Data, const sgx_epid_group_id_t& gid);
	SGXRAMessage2(Json::Value& msg);
	~SGXRAMessage2();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg2_t& GetMsg2Data() const;

	bool IsRLValid() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	sgx_ra_msg2_t* m_msg2Data;
	std::string m_rl;
	bool m_isRLValid;
};