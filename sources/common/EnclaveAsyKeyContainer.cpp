#include "EnclaveAsyKeyContainer.h"

#include <cstring>

EnclaveAsyKeyContainer & EnclaveAsyKeyContainer::GetInstance()
{
	static EnclaveAsyKeyContainer inst;
	return inst;
}

EnclaveAsyKeyContainer::EnclaveAsyKeyContainer()
{
	sgx_ecc_state_handle_t eccContext;
	m_status = sgx_ecc256_open_context(&eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}

	m_status = sgx_ecc256_create_key_pair(&m_signPriKey, &m_signPubKey, eccContext);
	if (m_status != SGX_SUCCESS)
	{
		return;
	}
}

EnclaveAsyKeyContainer::~EnclaveAsyKeyContainer()
{
	Clear();
}

void EnclaveAsyKeyContainer::Clear()
{
	std::memset(&m_signPriKey, 0, sizeof(sgx_ec256_private_t));
}
