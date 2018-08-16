#include "RACryptoManager.h"

#include "EnclaveAsyKeyContainer.h"

RACryptoManager::RACryptoManager() :
	m_keyContainer(EnclaveAsyKeyContainer::GetInstance()),
	m_eccContext(nullptr),
	m_status(SGX_SUCCESS)
{
	m_status = sgx_ecc256_open_context(&m_eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}
	m_status = m_keyContainer.m_status;
}

RACryptoManager::~RACryptoManager()
{
	sgx_ecc256_close_context(m_eccContext);
	m_eccContext = nullptr;
}

const sgx_ecc_state_handle_t & RACryptoManager::GetECC() const
{
	return m_eccContext;
}

const sgx_ec256_private_t & RACryptoManager::GetSignPriKey() const
{
	return m_keyContainer.m_signPriKey;
}

const sgx_ec256_public_t & RACryptoManager::GetSignPubKey() const
{
	return m_keyContainer.m_signPubKey;
}

sgx_status_t RACryptoManager::GetStatus() const
{
	return m_status;
}
