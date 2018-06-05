#include "SGXCryptoManager.h"

#include <cstring>

SGXCryptoManager::SGXCryptoManager() :
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

SGXCryptoManager::~SGXCryptoManager()
{
	sgx_ecc256_close_context(m_eccContext);
	m_eccContext = nullptr;
}

void SGXCryptoManager::SetSignKeySign(const sgx_ec256_signature_t & sign)
{
	std::memcpy(&m_signKeySign, &sign, sizeof(sgx_ec256_signature_t));
}

void SGXCryptoManager::SetEncrKeySign(const sgx_ec256_signature_t & sign)
{
	std::memcpy(&m_encrKeySign, &sign, sizeof(sgx_ec256_signature_t));
}

const sgx_ecc_state_handle_t & SGXCryptoManager::GetECC() const
{
	return m_eccContext;
}

const sgx_ec256_private_t & SGXCryptoManager::GetSignPriKey() const
{
	return m_signPriKey;
}

const sgx_ec256_private_t & SGXCryptoManager::GetEncrPriKey() const
{
	return m_encrPriKey;
}

const sgx_ec256_public_t & SGXCryptoManager::GetSignPubKey() const
{
	return m_signPubKey;
}

const sgx_ec256_public_t & SGXCryptoManager::GetEncrPubKey() const
{
	return m_encrPubKey;
}

const sgx_ec256_signature_t & SGXCryptoManager::GetSignKeySign() const
{
	return m_signKeySign;
}

const sgx_ec256_signature_t & SGXCryptoManager::GetEncrKeySign() const
{
	return m_encrKeySign;
}

sgx_status_t SGXCryptoManager::GetStatus() const
{
	return m_status;
}
