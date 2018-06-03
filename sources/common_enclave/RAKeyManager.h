#pragma once

#include <sgx_ecp_types.h>
#include <sgx_tcrypto.h>

class RAKeyManager
{
public:
	RAKeyManager() = delete;
	RAKeyManager(const sgx_ec256_public_t& signKey);
	~RAKeyManager();

	void SetSignKey(const sgx_ec256_public_t& signKey);
	void SetEncryptKey(const sgx_ec256_public_t& encryptKey);
	void SetSharedKey(const sgx_ec256_dh_shared_t& sharedKey);
	void SetSMK(const sgx_ec_key_128bit_t& smk);
	void SetMK(const sgx_ec_key_128bit_t& mk);
	void SetSK(const sgx_ec_key_128bit_t& sk);
	void SetVK(const sgx_ec_key_128bit_t& vk);

	sgx_ec256_public_t& GetSignKey();
	sgx_ec256_public_t& GetEncryptKey();
	sgx_ec256_dh_shared_t& GetSharedKey();
	sgx_ec_key_128bit_t& GetSMK();
	sgx_ec_key_128bit_t& GetMK();
	sgx_ec_key_128bit_t& GetSK();
	sgx_ec_key_128bit_t& GetVK();

private:
	sgx_ec256_public_t m_signKey;
	sgx_ec256_public_t m_encryptKey;

	sgx_ec256_dh_shared_t m_sharedKey;

	sgx_ec_key_128bit_t m_smk;
	sgx_ec_key_128bit_t m_mk;
	sgx_ec_key_128bit_t m_sk;
	sgx_ec_key_128bit_t m_vk;
};
