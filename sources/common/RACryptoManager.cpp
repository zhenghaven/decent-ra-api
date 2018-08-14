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
}

RACryptoManager::~RACryptoManager()
{
	sgx_ecc256_close_context(m_eccContext);
	m_eccContext = nullptr;
	std::memset(&m_signPriKey, 0, sizeof(sgx_ec256_private_t));
}

const sgx_ecc_state_handle_t & RACryptoManager::GetECC() const
{
	return m_eccContext;
}

const sgx_ec256_private_t & RACryptoManager::GetSignPriKey() const
{
	return m_signPriKey;
}

const sgx_ec256_public_t & RACryptoManager::GetSignPubKey() const
{
	return m_signPubKey;
}

sgx_status_t RACryptoManager::GetStatus() const
{
	return m_status;
}
