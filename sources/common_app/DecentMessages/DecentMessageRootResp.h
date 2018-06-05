#pragma once

#include "DecentMessage.h"

#include <sgx_tcrypto.h>

class DecentMessageRootResp : public DecentMessage
{
public:
	DecentMessageRootResp() = delete;
	DecentMessageRootResp(const std::string& senderID, 
		const sgx_ec256_private_t& inPriSignKey, const sgx_aes_gcm_128bit_tag_t& inPriSignKeyMac, 
		const sgx_ec256_public_t& inPubSignKey, const sgx_aes_gcm_128bit_tag_t& inPubSignKeyMac,
		const sgx_ec256_private_t& inPriEncrKey, const sgx_aes_gcm_128bit_tag_t& inPriEncrKeyMac,
		const sgx_ec256_public_t& inPubEncrKey, const sgx_aes_gcm_128bit_tag_t& inPubEncrKeyMac);
	DecentMessageRootResp(Json::Value& msg);
	~DecentMessageRootResp();

	virtual Type GetType() const override;

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual const sgx_ec256_private_t& GetPriSignKey() const;
	virtual const sgx_aes_gcm_128bit_tag_t& GetPriSignKeyMac() const;
	virtual const sgx_ec256_public_t& GetPubSignKey() const;
	virtual const sgx_aes_gcm_128bit_tag_t& GetPubSignKeyMac() const;

	virtual const sgx_ec256_private_t& GetPriEncrKey() const;
	virtual const sgx_aes_gcm_128bit_tag_t& GetPriEncrKeyMac() const;
	virtual const sgx_ec256_public_t& GetPubEncrKey() const;
	virtual const sgx_aes_gcm_128bit_tag_t& GetPubEncrKeyMac() const;
protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	sgx_ec256_private_t m_priSignKey;
	sgx_aes_gcm_128bit_tag_t m_priSignKeyMac;
	sgx_ec256_public_t m_pubSignKey;
	sgx_aes_gcm_128bit_tag_t m_pubSignKeyMac;

	sgx_ec256_private_t m_priEncrKey;
	sgx_aes_gcm_128bit_tag_t m_priEncrKeyMac;
	sgx_ec256_public_t m_pubEncrKey;
	sgx_aes_gcm_128bit_tag_t m_pubEncrKeyMac;
};
