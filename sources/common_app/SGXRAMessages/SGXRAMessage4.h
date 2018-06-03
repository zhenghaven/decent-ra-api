#pragma once

#include "SGXRAMessage.h"

#include <json/json.h>

//Forward Declarations:
struct _ra_msg4_t;
typedef _ra_msg4_t sgx_ra_msg4_t;
struct _sgx_ec256_signature_t;
typedef _sgx_ec256_signature_t sgx_ec256_signature_t;

class SGXRAMessage4 : public SGXRAMessage
{
public:
	SGXRAMessage4() = delete;
	SGXRAMessage4(const std::string& senderID, const sgx_ra_msg4_t& msg4Data, const sgx_ec256_signature_t& signature);
	SGXRAMessage4(Json::Value& msg);
	~SGXRAMessage4();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	const sgx_ra_msg4_t& GetMsg4Data() const;

	const sgx_ec256_signature_t& GetMsg4Signature() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	sgx_ra_msg4_t* m_msg4Data;
	sgx_ec256_signature_t* m_signature;
};
