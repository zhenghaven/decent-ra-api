#pragma once

#include "../common_app/EnclaveMessages.h"

#include <sgx_tcrypto.h>

class SimpleMessage : public EnclaveMessages
{
public:
	SimpleMessage() = delete;
	SimpleMessage(const std::string& senderID, const uint64_t& secret, const sgx_aes_gcm_128bit_tag_t& inSecretMac);
	SimpleMessage(Json::Value& msg);
	~SimpleMessage();

	virtual std::string GetMessgaeSubTypeStr() const override;

	const uint64_t& GetSecret() const;
	const sgx_aes_gcm_128bit_tag_t& GetSecretMac() const;

	virtual std::string ToJsonString() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	uint64_t m_secret;
	sgx_aes_gcm_128bit_tag_t m_secretMac;
};