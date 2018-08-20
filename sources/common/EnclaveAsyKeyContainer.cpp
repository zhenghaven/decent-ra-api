#include "EnclaveAsyKeyContainer.h"

#include <cstring>
#include <atomic>

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

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, std::shared_ptr<const PrivateKeyWrap>(new const PrivateKeyWrap(tmpPrv)));
	std::atomic_store(&m_signPubKey, std::shared_ptr<const sgx_ec256_public_t>(new const sgx_ec256_public_t(tmpPub)));
#else
	m_signPriKey = std::shared_ptr<const PrivateKeyWrap>(new const PrivateKeyWrap(tmpPrv));
	m_signPubKey = std::shared_ptr<const sgx_ec256_public_t>(new const sgx_ec256_public_t(tmpPub));
#endif // DECENT_THREAD_SAFETY_HIGH

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
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPriKey);
#else
	return m_signPriKey;
#endif // !DECENT_THREAD_SAFETY_HIGH
}

std::shared_ptr<const sgx_ec256_public_t> EnclaveAsyKeyContainer::GetSignPubKey() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPubKey);
#else
	return m_signPubKey;
#endif // !DECENT_THREAD_SAFETY_HIGH
}

void EnclaveAsyKeyContainer::UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const sgx_ec256_public_t> pub)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, prv);
	std::atomic_store(&m_signPubKey, pub);
#else
	m_signPriKey = prv;
	m_signPubKey = pub;
#endif // !DECENT_THREAD_SAFETY_HIGH
}
