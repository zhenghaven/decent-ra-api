#include "RACryptoManager.h"

#include <cstring>

RACryptoManager::RACryptoManager() :
	m_eccContext(nullptr),
	m_status(SGX_SUCCESS)
{
	m_status = sgx_ecc256_open_context(&m_eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}

	m_status = sgx_ecc256_create_key_pair(&m_signPriKey, &m_signPubKey, m_eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}

	m_status = sgx_ecc256_create_key_pair(&m_encrPriKey, &m_encrPubKey, m_eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}

	m_status = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&m_signPubKey), sizeof(sgx_ec256_public_t), &m_signPriKey, &m_signKeySign, m_eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}

	m_status = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&m_encrPubKey), sizeof(sgx_ec256_public_t), &m_signPriKey, &m_encrKeySign, m_eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}
}

RACryptoManager::~RACryptoManager()
{
	sgx_ecc256_close_context(m_eccContext);
	m_eccContext = nullptr;
	std::memset(&m_signPriKey, 0, sizeof(sgx_ec256_private_t));
	std::memset(&m_encrPriKey, 0, sizeof(sgx_ec256_private_t));
}

void RACryptoManager::SetSignKeySign(const sgx_ec256_signature_t & sign)
{
	std::memcpy(&m_signKeySign, &sign, sizeof(sgx_ec256_signature_t));
}

void RACryptoManager::SetEncrKeySign(const sgx_ec256_signature_t & sign)
{
	std::memcpy(&m_encrKeySign, &sign, sizeof(sgx_ec256_signature_t));
}

const sgx_ecc_state_handle_t & RACryptoManager::GetECC() const
{
	return m_eccContext;
}

const sgx_ec256_private_t & RACryptoManager::GetSignPriKey() const
{
	return m_signPriKey;
}

const sgx_ec256_private_t & RACryptoManager::GetEncrPriKey() const
{
	return m_encrPriKey;
}

const sgx_ec256_public_t & RACryptoManager::GetSignPubKey() const
{
	return m_signPubKey;
}

const sgx_ec256_public_t & RACryptoManager::GetEncrPubKey() const
{
	return m_encrPubKey;
}

const sgx_ec256_signature_t & RACryptoManager::GetSignKeySign() const
{
	return m_signKeySign;
}

const sgx_ec256_signature_t & RACryptoManager::GetEncrKeySign() const
{
	return m_encrKeySign;
}

sgx_status_t RACryptoManager::GetStatus() const
{
	return m_status;
}
