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
	sgx_status_t status = sgx_ecc256_open_context(&eccContext);
	if (status != SGX_SUCCESS)
	{
		m_isValid = false;
		return;
	}
	sgx_ec256_public_t tmpPub;
	PrivateKeyWrap tmpPrv;
	status = sgx_ecc256_create_key_pair(&(tmpPrv.m_prvKey), &tmpPub, eccContext);
	if (status != SGX_SUCCESS)
	{
		m_isValid = false;
		return;
	}
	
	m_signPriKey.store(new std::shared_ptr<const PrivateKeyWrap>(new const PrivateKeyWrap(tmpPrv)));
	m_signPubKey.store(new std::shared_ptr<const sgx_ec256_public_t>(new const sgx_ec256_public_t(tmpPub)));

	sgx_ecc256_close_context(eccContext);
	m_isValid = true;
}

EnclaveAsyKeyContainer::~EnclaveAsyKeyContainer()
{
}

bool EnclaveAsyKeyContainer::IsValid() const
{
	return m_isValid;
}

std::shared_ptr<const PrivateKeyWrap> EnclaveAsyKeyContainer::GetSignPrvKey() const
{
	return *(m_signPriKey.load());
}

std::shared_ptr<const sgx_ec256_public_t> EnclaveAsyKeyContainer::GetSignPubKey() const
{
	return *(m_signPubKey.load());
}

void EnclaveAsyKeyContainer::UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const sgx_ec256_public_t> pub)
{
	//std::lock_guard<std::mutex> lock(m_updateLock);
	m_signPriKey.store(new std::shared_ptr<const PrivateKeyWrap>(prv));
	m_signPubKey.store(new std::shared_ptr<const sgx_ec256_public_t>(pub));
}
