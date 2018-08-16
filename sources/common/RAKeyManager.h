#pragma once

#include <sgx_ecp_types.h>
#include <sgx_tcrypto.h>
#include <sgx_tae_service.h>

class RAKeyManager
{
public:
	RAKeyManager();
	RAKeyManager(const RAKeyManager& other);
	RAKeyManager(RAKeyManager&& other);
	RAKeyManager(const sgx_ec256_public_t& signKey);
	~RAKeyManager();

	RAKeyManager& operator=(const RAKeyManager& rhs);
	RAKeyManager& RAKeyManager::operator=(RAKeyManager&& rhs) noexcept;

	void SetSignKey(const sgx_ec256_public_t& signKey);
	void SetSharedKey(const sgx_ec256_dh_shared_t& sharedKey);
	void SetSMK(const sgx_ec_key_128bit_t& smk);
	void SetMK(const sgx_ec_key_128bit_t& mk);
	void SetSK(const sgx_ec_key_128bit_t& sk);
	void SetVK(const sgx_ec_key_128bit_t& vk);
	void SetSecProp(const sgx_ps_sec_prop_desc_t& secProp);

	sgx_ec256_public_t& GetSignKey();
	sgx_ec256_dh_shared_t& GetSharedKey();
	sgx_ec_key_128bit_t& GetSMK();
	sgx_ec_key_128bit_t& GetMK();
	sgx_ec_key_128bit_t& GetSK();
	sgx_ec_key_128bit_t& GetVK();
	sgx_ps_sec_prop_desc_t& GetSecProp();

	const sgx_ec256_public_t& GetSignKey() const;
	const sgx_ec256_dh_shared_t& GetSharedKey() const;
	const sgx_ec_key_128bit_t& GetSMK() const;
	const sgx_ec_key_128bit_t& GetMK() const;
	const sgx_ec_key_128bit_t& GetSK() const;
	const sgx_ec_key_128bit_t& GetVK() const;
	const sgx_ps_sec_prop_desc_t& GetSecProp() const;

private:
	sgx_ec256_public_t m_signKey;

	sgx_ec256_dh_shared_t m_sharedKey;

	sgx_ec_key_128bit_t m_smk;
	sgx_ec_key_128bit_t m_mk;
	sgx_ec_key_128bit_t m_sk;
	sgx_ec_key_128bit_t m_vk;

	sgx_ps_sec_prop_desc_t m_secProp;
};
