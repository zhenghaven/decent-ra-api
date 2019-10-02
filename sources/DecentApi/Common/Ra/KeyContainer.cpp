#include "KeyContainer.h"

#include <cstring>

#include <exception>

#include "../Common.h"
#include "../make_unique.h"
#include "../MbedTls/MbedTlsObjects.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;

namespace
{
	static std::unique_ptr<EcKeyPair<EcKeyType::SECP256R1> > CosntructKeyPair(const std::shared_ptr<const general_secp256r1_public_t>& pub, const std::shared_ptr<const Decent::PrivateKeyWrap>& prv)
	{
		std::unique_ptr<EcKeyPair<EcKeyType::SECP256R1> > keyPair;
		if (!pub || !prv)
		{
			throw Decent::RuntimeException("Null pointer received.");
		}

		return make_unique<EcKeyPair<EcKeyType::SECP256R1> >(prv->m_prvKey.r, pub->x, pub->y);
	}

	static general_secp256r1_public_t ConstructPublicKey(const EcKeyPair<EcKeyType::SECP256R1>& keyPair)
	{
		general_secp256r1_public_t res;
		keyPair.ToPublicBinary(res.x, res.y);
		return res;
	}

	static Decent::PrivateKeyWrap ConstructPrivateKey(const EcKeyPair<EcKeyType::SECP256R1>& keyPair)
	{
		Decent::PrivateKeyWrap res;
		keyPair.ToPrivateBinary(res.m_prvKey.r);
		return res;
	}
}

KeyContainer::KeyContainer(std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<Decent::PrivateKeyWrap> > keyPair) :
	m_signPubKey(std::move(keyPair.first)),
	m_signPrvKey(std::move(keyPair.second)),
	m_signPrvKeyObj(std::move(CosntructKeyPair(m_signPubKey, m_signPrvKey)))
{
}

KeyContainer::KeyContainer(std::unique_ptr<EcKeyPair<EcKeyType::SECP256R1> > keyPair) :
	m_signPubKey(std::make_shared<general_secp256r1_public_t>(ConstructPublicKey(*keyPair))),
	m_signPrvKey(std::make_shared<Decent::PrivateKeyWrap>(ConstructPrivateKey(*keyPair))),
	m_signPrvKeyObj(std::move(keyPair))
{
}

KeyContainer::~KeyContainer()
{
}

std::shared_ptr<const Decent::PrivateKeyWrap> KeyContainer::GetSignPrvKey() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPrvKey);
#else
	return m_signPrvKey;
#endif // DECENT_THREAD_SAFETY_HIGH
}

std::shared_ptr<const general_secp256r1_public_t> KeyContainer::GetSignPubKey() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPubKey);
#else
	return m_signPubKey;
#endif // DECENT_THREAD_SAFETY_HIGH
}

std::shared_ptr<const EcKeyPair<EcKeyType::SECP256R1> > KeyContainer::GetSignKeyPair() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPrvKeyObj);
#else
	return m_signPrvKeyObj;
#endif // DECENT_THREAD_SAFETY_HIGH
}

void KeyContainer::SetSignPrvKey(std::shared_ptr<const Decent::PrivateKeyWrap> key)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPrvKey, key);
#else
	m_signPrvKey = key;
#endif // DECENT_THREAD_SAFETY_HIGH
}

void KeyContainer::SetSignPubKey(std::shared_ptr<const general_secp256r1_public_t> key)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPubKey, key);
#else
	m_signPubKey = key;
#endif // DECENT_THREAD_SAFETY_HIGH
}

void KeyContainer::SetSignKeyPair(std::shared_ptr<const EcKeyPair<EcKeyType::SECP256R1> > key)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_signPrvKeyObj, key);
#else
	m_signPrvKeyObj = key;
#endif // DECENT_THREAD_SAFETY_HIGH
}
