#pragma once

#include "DecentSGXEnclaveImp.h"

class ExampleEnclave : public DecentSGXEnclaveImp
{
public:
	using DecentSGXEnclaveImp::DecentSGXEnclaveImp;

	~ExampleEnclave();

	virtual sgx_status_t GetSimpleSecret(const std::string& id, uint64_t& secret, sgx_aes_gcm_128bit_tag_t& outSecretMac);
	virtual sgx_status_t ProcessSimpleSecret(const std::string& id, const uint64_t& secret, const sgx_aes_gcm_128bit_tag_t& inSecretMac);
	virtual sgx_status_t CryptoTest(const uint8_t *p_data, uint32_t data_size, const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature);
private:

};
