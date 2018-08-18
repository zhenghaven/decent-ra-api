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

sgx_status_t RACryptoManager::GetStatus() const
{
	return m_status;
}
