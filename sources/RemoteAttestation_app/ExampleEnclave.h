#pragma once

#include "../common_app/SGX/SGXDecentEnclave.h"

class ExampleEnclave : public SGXDecentEnclave
{
public:
	using SGXDecentEnclave::SGXDecentEnclave;

	~ExampleEnclave();

	virtual sgx_status_t GetSimpleSecret(const std::string& id, uint64_t& secret, sgx_aes_gcm_128bit_tag_t& outSecretMac);
	virtual sgx_status_t ProcessSimpleSecret(const std::string& id, const uint64_t& secret, const sgx_aes_gcm_128bit_tag_t& inSecretMac);
	virtual sgx_status_t CryptoTest(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len, sgx_aes_gcm_128bit_tag_t *p_out_mac);
private:

};
