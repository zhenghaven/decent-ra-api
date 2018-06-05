#pragma once

#include "DecentMessage.h"

#include <sgx_tcrypto.h>

class DecentMessageMsg0 : public DecentMessage
{
public:
	DecentMessageMsg0() = delete;
	DecentMessageMsg0(const std::string& senderID, const sgx_ec256_public_t& inSignKey, const sgx_ec256_signature_t& inSignSign, const sgx_ec256_public_t& inEncrKey, const sgx_ec256_signature_t& inEncrSign);
	DecentMessageMsg0(Json::Value& msg);
	~DecentMessageMsg0();

	virtual Type GetType() const override;

	virtual std::string GetMessgaeSubTypeStr() const override;


	virtual const sgx_ec256_public_t& GetSignKey() const;
	virtual const sgx_ec256_signature_t& GetSignSign() const;
	virtual const sgx_ec256_public_t& GetEncrKey() const;
	virtual const sgx_ec256_signature_t& GetEncrSign() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	sgx_ec256_public_t m_signKey;
	sgx_ec256_signature_t m_signSign;
	sgx_ec256_public_t m_encrKey;
	sgx_ec256_signature_t m_encrSign;
};