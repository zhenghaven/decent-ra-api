#include "RAKeyManager.h"

#include <cstring>
#include <cstdlib>

#include <sgx_tcrypto.h>

#include "../common/sgx_crypto_tools.h"

RAKeyManager::RAKeyManager(const sgx_ec256_public_t & signKey) :
	m_signKey(signKey)//,
	//m_encryptKey(nullptr),
	//m_sharedKey(nullptr),
	//m_smk(nullptr),
	//m_mk(nullptr),
	//m_sk(nullptr),
	//m_vk(nullptr)
{
}

RAKeyManager::~RAKeyManager()
{
	//delete m_signKey;
	//delete m_encryptKey;
	//delete m_sharedKey;
	//delete m_smk;
	//delete m_mk;
	//delete m_sk;
	//delete m_vk;
}

void RAKeyManager::SetSignKey(const sgx_ec256_public_t & signKey)
{
	//if (m_signKey)
	//{
		std::memcpy(&m_signKey, &signKey, sizeof(sgx_ec256_public_t));
	//}
	//else
	//{
	//	m_signKey = new sgx_ec256_public_t(signKey);
	//}
}

void RAKeyManager::SetEncryptKey(const sgx_ec256_public_t & encryptKey)
{
	//if (m_encryptKey)
	//{
		std::memcpy(&m_encryptKey, &encryptKey, sizeof(sgx_ec256_public_t));
	//}
	//else
	//{
	//	m_encryptKey = new sgx_ec256_public_t(encryptKey);
	//}
}

void RAKeyManager::SetSharedKey(const sgx_ec256_dh_shared_t & sharedKey)
{
	//if (m_sharedKey)
	//{
		std::memcpy(&m_sharedKey, &sharedKey, sizeof(sgx_ec256_dh_shared_t));
	//}
	//else
	//{
	//	m_sharedKey = new sgx_ec256_dh_shared_t(sharedKey);
	//}
}

void RAKeyManager::SetSMK(const sgx_ec_key_128bit_t & smk)
{
	//if (m_smk)
	//{
		std::memcpy(&m_smk, &smk, sizeof(sgx_ec_key_128bit_t));
	//}
	//else
	//{
	//	m_smk =reinterpret_cast<sgx_ec_key_128bit_t*>(new sgx_ec_key_128bit_t);
	//	std::memcpy(m_smk, &smk, sizeof(sgx_ec_key_128bit_t));
	//}
}

void RAKeyManager::SetMK(const sgx_ec_key_128bit_t & mk)
{
	//if (m_mk)
	//{
		std::memcpy(&m_mk, &mk, sizeof(sgx_ec_key_128bit_t));
	//}
	//else
	//{
	//	m_mk = reinterpret_cast<sgx_ec_key_128bit_t*>(new sgx_ec_key_128bit_t);
	//	std::memcpy(m_mk, &mk, sizeof(sgx_ec_key_128bit_t));
	//}
}

void RAKeyManager::SetSK(const sgx_ec_key_128bit_t & sk)
{
	//if (m_sk)
	//{
		std::memcpy(&m_sk, &sk, sizeof(sgx_ec_key_128bit_t));
	//}
	//else
	//{
	//	m_sk = reinterpret_cast<sgx_ec_key_128bit_t*>(new sgx_ec_key_128bit_t);
	//	std::memcpy(m_sk, &sk, sizeof(sgx_ec_key_128bit_t));
	//}
}

void RAKeyManager::SetVK(const sgx_ec_key_128bit_t & vk)
{
	//if (m_vk)
	//{
		std::memcpy(&m_vk, &vk, sizeof(sgx_ec_key_128bit_t));
	//}
	//else
	//{
	//	m_vk = reinterpret_cast<sgx_ec_key_128bit_t*>(new sgx_ec_key_128bit_t);
	//	std::memcpy(m_vk, &vk, sizeof(sgx_ec_key_128bit_t));
	//}
}

void RAKeyManager::SetSecProp(const sgx_ps_sec_prop_desc_t & secProp)
{
	std::memcpy(&m_secProp, &secProp, sizeof(sgx_ps_sec_prop_desc_t));
}

sgx_status_t RAKeyManager::GenerateSharedKeySet(const sgx_ec256_private_t & priKey, const sgx_ecc_state_handle_t& ecc_handle)
{
	sgx_status_t res = SGX_SUCCESS;
	res = sgx_ecc256_compute_shared_dhkey(const_cast<sgx_ec256_private_t*>(&(priKey)), &m_encryptKey, &m_sharedKey, ecc_handle);
	if (res != SGX_SUCCESS)
	{
		return res;
	}

	res = sp_derive_key_type(&m_sharedKey, SGX_DERIVE_KEY_SMK, &m_smk);
	if (res != SGX_SUCCESS)
	{
		return res;
	}

	res = sp_derive_key_type(&m_sharedKey, SGX_DERIVE_KEY_MK, &m_mk);
	if (res != SGX_SUCCESS)
	{
		return res;
	}

	res = sp_derive_key_type(&m_sharedKey, SGX_DERIVE_KEY_SK, &m_sk);
	if (res != SGX_SUCCESS)
	{
		return res;
	}

	res = sp_derive_key_type(&m_sharedKey, SGX_DERIVE_KEY_VK, &m_vk);
	if (res != SGX_SUCCESS)
	{
		return res;
	}

	return SGX_SUCCESS;
}

sgx_ec256_public_t & RAKeyManager::GetSignKey()
{
	return m_signKey;
}

sgx_ec256_public_t & RAKeyManager::GetEncryptKey()
{
	return m_encryptKey;
}

sgx_ec256_dh_shared_t & RAKeyManager::GetSharedKey()
{
	return m_sharedKey;
}

sgx_ec_key_128bit_t & RAKeyManager::GetSMK()
{
	return m_smk;
}

sgx_ec_key_128bit_t & RAKeyManager::GetMK()
{
	return m_mk;
}

sgx_ec_key_128bit_t & RAKeyManager::GetSK()
{
	return m_sk;
}

sgx_ec_key_128bit_t & RAKeyManager::GetVK()
{
	return m_vk;
}

sgx_ps_sec_prop_desc_t & RAKeyManager::GetSecProp()
{
	return m_secProp;
}
