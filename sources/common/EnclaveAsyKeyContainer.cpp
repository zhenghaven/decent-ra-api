#include "EnclaveAsyKeyContainer.h"

#include <cstring>

#include <openssl/ec.h>

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

static inline void GeneratePublicKeyPemString(std::shared_ptr<std::string> outStr, const sgx_ec256_public_t& inPubKey)
{
	EC_KEY* pubKey = EC_KEY_new();
	if (!pubKey || !ECKeyPubSGX2OpenSSL(&inPubKey, pubKey, nullptr))
	{
		EC_KEY_free(pubKey);
		return;
	}
	*outStr = ECKeyPubGetPEMStr(pubKey);
	EC_KEY_free(pubKey);
}

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
	std::shared_ptr<sgx_ec256_public_t> tmpPub(new sgx_ec256_public_t);
	std::shared_ptr<PrivateKeyWrap> tmpPrv(new PrivateKeyWrap);

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

	std::shared_ptr<std::string> pubPem;
	GeneratePublicKeyPemString(pubPem, *tmpPub);

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, tmpPrv);
	std::atomic_store(&m_signPubKey, tmpPub);
	std::atomic_store(&m_signPubPem, pubPem);
#else
	m_signPriKey = tmpPrv;
	m_signPubKey = tmpPub;
	m_signPubPem = pubPem;
#endif // DECENT_THREAD_SAFETY_HIGH

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

std::shared_ptr<const std::string> EnclaveAsyKeyContainer::GetSignPubPem() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPubPem);
#else
	return m_signPubPem;
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

	std::shared_ptr<std::string> pubPem;
	GeneratePublicKeyPemString(pubPem, *pub);

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPriKey, prv);
	std::atomic_store(&m_signPubKey, pub);
	std::atomic_store(&m_signPubPem, pubPem);
#else
	m_signPriKey = prv;
	m_signPubKey = pub;
	m_signPubPem = pubPem;
#endif // !DECENT_THREAD_SAFETY_HIGH
}
