#include "CryptoKeyContainer.h"

#include <cstring>

#include "MbedTlsObjects.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#ifdef ENCLAVE_ENVIRONMENT
constexpr bool IS_IN_ENCLAVE_SIDE = true;
#else
constexpr bool IS_IN_ENCLAVE_SIDE = false;
#endif // ENCLAVE_ENVIRONMENT

using namespace MbedTlsObj;

CryptoKeyContainer& CryptoKeyContainer::GetInstance()
{
	static CryptoKeyContainer inst;
	return inst;
}

CryptoKeyContainer::CryptoKeyContainer(const std::pair<general_secp256r1_public_t*, PrivateKeyWrap*>& keyPair) :
	CryptoKeyContainer(keyPair.first, keyPair.second, keyPair.second ? new ECKeyPair(keyPair.second->m_prvKey) : nullptr)
{
}

CryptoKeyContainer::CryptoKeyContainer(MbedTlsObj::ECKeyPair * keyPair) :
	CryptoKeyContainer(keyPair ? keyPair->ToGeneralPublicKey() : nullptr,
		keyPair ? keyPair->ToGeneralPrivateKeyWrap() :nullptr,
		keyPair)
{
}

CryptoKeyContainer::CryptoKeyContainer(general_secp256r1_public_t * pubKey, PrivateKeyWrap * prvKey, MbedTlsObj::ECKeyPair * keyPair) :
	m_signPubKey(pubKey),
	m_signPrvKey(prvKey),
	m_signPrvKeyObj(keyPair),
	k_isValid(pubKey && prvKey && keyPair && *keyPair)
{
}

CryptoKeyContainer::~CryptoKeyContainer()
{
}

CryptoKeyContainer::operator bool() const
{
	return k_isValid;
}

std::shared_ptr<const PrivateKeyWrap> CryptoKeyContainer::GetSignPrvKey() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPrvKey);
#else
	return m_signPrvKey;
#endif // DECENT_THREAD_SAFETY_HIGH
}

std::shared_ptr<const general_secp256r1_public_t> CryptoKeyContainer::GetSignPubKey() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPubKey);
#else
	return m_signPubKey;
#endif // DECENT_THREAD_SAFETY_HIGH
}

std::shared_ptr<const ECKeyPair> CryptoKeyContainer::GetSignKeyPair() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPrvKeyObj);
#else
	return m_signPrvKeyObj;
#endif // DECENT_THREAD_SAFETY_HIGH
}

bool CryptoKeyContainer::UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const general_secp256r1_public_t> pub)
{
	if (!prv || !pub)
	{
		return false;
	}
	//COMMON_PRINTF("Updating Pub Sign Key for %s Side to: %s\n",
	//	IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
	//	SerializeStruct(*pub).c_str());
//	COMMON_PRINTF("Updating Prv Sign Key for %s Side to: %s\n",
//		IS_IN_ENCLAVE_SIDE ? "Enclave" : "App",
//		SerializeStruct(prv->m_prvKey).c_str());

	std::shared_ptr<const ECKeyPair> tmpPrvObj(new ECKeyPair(prv->m_prvKey));
	if (!tmpPrvObj || !*tmpPrvObj)
	{
		return false;
	}

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPrvKey, prv);
	std::atomic_store(&m_signPubKey, pub);
	std::atomic_store(&m_signPrvKeyObj, tmpPrvObj);
#else
	m_signPrvKey = prv;
	m_signPubKey = pub;
	m_signPrvKeyObj = tmpPrvObj;
#endif // DECENT_THREAD_SAFETY_HIGH

	return true;
}

bool CryptoKeyContainer::UpdateSignKeyPair(std::shared_ptr<const MbedTlsObj::ECKeyPair> keyPair)
{
	if (!keyPair || !*keyPair)
	{
		return false;
	}
	
	std::shared_ptr<const PrivateKeyWrap> prv(keyPair->ToGeneralPrivateKeyWrap());
	std::shared_ptr<const general_secp256r1_public_t> pub(keyPair->ToGeneralPublicKey());
	if (!prv || !pub)
	{
		return false;
	}

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPrvKey, prv);
	std::atomic_store(&m_signPubKey, pub);
	std::atomic_store(&m_signPrvKeyObj, tmpPrvObj);
#else
	m_signPrvKey = prv;
	m_signPubKey = pub;
	m_signPrvKeyObj = keyPair;
#endif // DECENT_THREAD_SAFETY_HIGH

	return true;
}
