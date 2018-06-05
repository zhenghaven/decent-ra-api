#pragma once

#include "DecentMessage.h"

#include <sgx_tcrypto.h>

class DecentMessageApplResp : public DecentMessage
{
public:
	DecentMessageApplResp() = delete;
	DecentMessageApplResp(const std::string& senderID, const sgx_ec256_signature_t& signSign, const sgx_aes_gcm_128bit_tag_t& signMac, const sgx_ec256_signature_t& encrSign, const sgx_aes_gcm_128bit_tag_t& encrMac);
	DecentMessageApplResp(Json::Value& msg);
	~DecentMessageApplResp();

	virtual Type GetType() const override;

	virtual std::string GetMessgaeSubTypeStr() const override;

	const sgx_ec256_signature_t& GetSignSign() const;
	const sgx_ec256_signature_t& GetEncrSign() const;

	const sgx_aes_gcm_128bit_tag_t& GetSignMac() const;
	const sgx_aes_gcm_128bit_tag_t& GetEncrMac() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	sgx_ec256_signature_t m_signSign;
	sgx_aes_gcm_128bit_tag_t m_signMac;
	sgx_ec256_signature_t m_encrSign;
	sgx_aes_gcm_128bit_tag_t m_encrMac;
};