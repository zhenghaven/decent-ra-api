#include "RAKeyManager.h"

#include <cstring>
#include <cstdlib>

#include <utility>

#include <sgx_tcrypto.h>

#include "../common/SGX/sgx_crypto_tools.h"

RAKeyManager::RAKeyManager()
{
}

RAKeyManager::RAKeyManager(const RAKeyManager & other)
{
	std::memcpy(&m_signKey, &(other.m_signKey), sizeof(sgx_ec256_public_t));
	std::memcpy(&m_encryptKey, &(other.m_encryptKey), sizeof(sgx_ec256_public_t));

	std::memcpy(&m_sharedKey, &(other.m_sharedKey), sizeof(sgx_ec256_dh_shared_t));

	std::memcpy(&m_smk, &(other.m_smk), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&m_mk, &(other.m_mk), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&m_sk, &(other.m_sk), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&m_vk, &(other.m_vk), sizeof(sgx_ec_key_128bit_t));
}

RAKeyManager::RAKeyManager(RAKeyManager && other) :
	m_signKey(std::move(other.m_signKey)),
	m_encryptKey(std::move(other.m_encryptKey)),
	m_sharedKey(std::move(other.m_sharedKey))
{//TODO: Fix this later.
	std::memcpy(&m_smk, &(other.m_smk), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&m_mk, &(other.m_mk), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&m_sk, &(other.m_sk), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&m_vk, &(other.m_vk), sizeof(sgx_ec_key_128bit_t));
}

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

RAKeyManager& RAKeyManager::operator=(const RAKeyManager& rhs) 
{
	if (&rhs != this) 
	{
		RAKeyManager tmp(rhs);
		std::swap(*this, tmp);
	}
	return *this;
}

RAKeyManager& RAKeyManager::operator=(RAKeyManager&& rhs) noexcept 
{
	std::swap(m_signKey, rhs.m_signKey);
	std::swap(m_encryptKey, rhs.m_encryptKey);

	std::swap(m_sharedKey, rhs.m_sharedKey);

	std::swap(m_smk, rhs.m_smk);
	std::swap(m_mk, rhs.m_mk);
	std::swap(m_sk, rhs.m_sk);
	std::swap(m_vk, rhs.m_vk);
	return *this;
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

const sgx_ec256_public_t & RAKeyManager::GetSignKey() const
{
	return m_signKey;
}

const sgx_ec256_public_t & RAKeyManager::GetEncryptKey() const
{
	return m_encryptKey;
}

const sgx_ec256_dh_shared_t & RAKeyManager::GetSharedKey() const
{
	return m_sharedKey;
}

const sgx_ec_key_128bit_t & RAKeyManager::GetSMK() const
{
	return m_smk;
}

const sgx_ec_key_128bit_t & RAKeyManager::GetMK() const
{
	return m_mk;
}

const sgx_ec_key_128bit_t & RAKeyManager::GetSK() const
{
	return m_sk;
}

const sgx_ec_key_128bit_t & RAKeyManager::GetVK() const
{
	return m_vk;
}

const sgx_ps_sec_prop_desc_t & RAKeyManager::GetSecProp() const
{
	return m_secProp;
}
