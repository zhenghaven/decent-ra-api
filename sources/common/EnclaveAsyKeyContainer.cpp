#include "EnclaveAsyKeyContainer.h"

#include <cstring>

#include "CommonTool.h"
#include "DataCoding.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#ifdef ENCLAVE_CODE
constexpr bool IS_IN_ENCLAVE_SIDE = true;
#else
constexpr bool IS_IN_ENCLAVE_SIDE = false;
#endif // ENCLAVE_CODE


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
	COMMON_PRINTF("Public Signing Key for %s Side Is: %s\n",
		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
		SerializeStruct(*std::atomic_load(&m_signPubKey)));
#else
	m_signPriKey = std::shared_ptr<const PrivateKeyWrap>(new const PrivateKeyWrap(tmpPrv));
	m_signPubKey = std::shared_ptr<const sgx_ec256_public_t>(new const sgx_ec256_public_t(tmpPub));
	COMMON_PRINTF("Public Signing Key for %s Side Is: %s\n", 
		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App", 
		SerializeStruct(*m_signPubKey).c_str());
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
	COMMON_PRINTF("Updating Pub Sign Key for %s Side to: %s\n",
		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
		SerializeStruct(*pub).c_str());
//	COMMON_PRINTF("Updating Prv Sign Key for %s Side to: %s\n",
//		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
//		SerializeStruct(prv->m_prvKey).c_str());
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, prv);
	std::atomic_store(&m_signPubKey, pub);
#else
	m_signPriKey = prv;
	m_signPubKey = pub;
#endif // !DECENT_THREAD_SAFETY_HIGH
}
