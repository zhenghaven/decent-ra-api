#include "EnclaveAsyKeyContainer.h"

#include <cstring>

#include "CommonTool.h"
#include "DataCoding.h"
#include "SGX/SGXOpenSSLConversions.h"

#include "OpenSSLTools.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#ifdef ENCLAVE_CODE
constexpr bool IS_IN_ENCLAVE_SIDE = true;
#else
constexpr bool IS_IN_ENCLAVE_SIDE = false;
#endif // ENCLAVE_CODE

namespace
{
	static std::shared_ptr<EnclaveAsyKeyContainer> g_instance;
}

const std::shared_ptr<EnclaveAsyKeyContainer> EnclaveAsyKeyContainer::GetInstance()
{
	if (!g_instance)
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		std::atomic_store(&g_instance, std::make_shared<EnclaveAsyKeyContainer>());
#else
		g_instance.reset(new EnclaveAsyKeyContainer);
#endif // !DECENT_THREAD_SAFETY_HIGH
	}
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&g_instance);
#else
	return g_instance;
#endif // !DECENT_THREAD_SAFETY_HIGH
}

void EnclaveAsyKeyContainer::SetInstance(std::shared_ptr<EnclaveAsyKeyContainer> instance)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&g_instance, instance);
#else
	g_instance.swap(instance);
#endif // !DECENT_THREAD_SAFETY_HIGH
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
	std::unique_ptr<sgx_ec256_public_t> tmpPub(new sgx_ec256_public_t);
	std::unique_ptr<PrivateKeyWrap> tmpPrv(new PrivateKeyWrap);

	status = sgx_ecc256_create_key_pair(&(tmpPrv->m_prvKey), tmpPub.get(), eccContext);
	if (status != SGX_SUCCESS)
	{
		m_isValid = false;
		return;
	}

	sgx_ecc256_close_context(eccContext);

	COMMON_PRINTF("Public Signing Key for %s Side Is: %s\n", 
		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App", 
		SerializeStruct(*tmpPub).c_str());

	std::unique_ptr<ECKeyPublic> tmpPubOpen(new ECKeyPublic(SgxEc256Type2General(*tmpPub)));
	std::unique_ptr<ECKeyPair> tmpPrvOpen(new ECKeyPair(SgxEc256Type2General(tmpPrv->m_prvKey)));

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, std::shared_ptr<const PrivateKeyWrap>(tmpPrv.release()));
	std::atomic_store(&m_signPubKey, std::shared_ptr<const sgx_ec256_public_t>(tmpPub.release()));
	std::atomic_store(&m_signPriKeyOpen, std::shared_ptr<const ECKeyPair>(tmpPrvOpen.release()));
	std::atomic_store(&m_signPubKeyOpen, std::shared_ptr<const ECKeyPublic>(tmpPubOpen.release()));
#else
	m_signPriKey.reset(tmpPrv.release());
	m_signPubKey.reset(tmpPub.release());
	m_signPriKeyOpen.reset(tmpPrvOpen.release());
	m_signPubKeyOpen.reset(tmpPubOpen.release());
#endif // DECENT_THREAD_SAFETY_HIGH

	m_isValid = true;
}

EnclaveAsyKeyContainer::EnclaveAsyKeyContainer(std::pair<std::unique_ptr<sgx_ec256_public_t>, std::unique_ptr<PrivateKeyWrap>> keyPair)
{
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

std::shared_ptr<const ECKeyPublic> EnclaveAsyKeyContainer::GetSignPubKeyOpenSSL() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPubKeyOpen);
#else
	return m_signPubKeyOpen;
#endif // !DECENT_THREAD_SAFETY_HIGH
}

std::shared_ptr<const ECKeyPair> EnclaveAsyKeyContainer::GetSignPrvKeyOpenSSL() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPriKeyOpen);
#else
	return m_signPriKeyOpen;
#endif // !DECENT_THREAD_SAFETY_HIGH
}

//std::shared_ptr<const std::string> EnclaveAsyKeyContainer::GetSignPubPem() const
//{
//#ifdef DECENT_THREAD_SAFETY_HIGH
//	return std::atomic_load(&m_signPubPem);
//#else
//	return m_signPubPem;
//#endif // !DECENT_THREAD_SAFETY_HIGH
//}

void EnclaveAsyKeyContainer::UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const sgx_ec256_public_t> pub)
{
	//COMMON_PRINTF("Updating Pub Sign Key for %s Side to: %s\n",
	//	IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
	//	SerializeStruct(*pub).c_str());
//	COMMON_PRINTF("Updating Prv Sign Key for %s Side to: %s\n",
//		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
//		SerializeStruct(prv->m_prvKey).c_str());

	std::unique_ptr<ECKeyPublic> tmpPubOpen(new ECKeyPublic(SgxEc256Type2General(*pub)));
	std::unique_ptr<ECKeyPair> tmpPrvOpen(new ECKeyPair(SgxEc256Type2General(prv->m_prvKey)));

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, prv);
	std::atomic_store(&m_signPubKey, pub);
	std::atomic_store(&m_signPriKeyOpen, std::shared_ptr<const ECKeyPair>(tmpPrvOpen.release()));
	std::atomic_store(&m_signPubKeyOpen, std::shared_ptr<const ECKeyPublic>(tmpPubOpen.release()));
#else
	m_signPriKey = prv;
	m_signPubKey = pub;
	m_signPriKeyOpen.reset(tmpPrvOpen.release());
	m_signPubKeyOpen.reset(tmpPubOpen.release());
#endif // !DECENT_THREAD_SAFETY_HIGH
}
