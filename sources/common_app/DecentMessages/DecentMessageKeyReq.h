#pragma once

#include "DecentMessage.h"

#include <sgx_tcrypto.h>

#include "../../common/Decent.h"

class DecentMessageKeyReq : public DecentMessage
{
public:
	DecentMessageKeyReq() = delete;
	DecentMessageKeyReq(const std::string& senderID, DecentNodeMode mode, sgx_ec256_public_t& signKey, sgx_ec256_public_t& encrKey);
	DecentMessageKeyReq(Json::Value& msg);
	~DecentMessageKeyReq();

	virtual Type GetType() const override;

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual DecentNodeMode GetMode() const;
	virtual const sgx_ec256_public_t& GetSignKey() const;
	virtual const sgx_ec256_public_t& GetEncrKey() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	DecentNodeMode m_mode;
	sgx_ec256_public_t m_signKey;
	sgx_ec256_public_t m_encrKey;
};