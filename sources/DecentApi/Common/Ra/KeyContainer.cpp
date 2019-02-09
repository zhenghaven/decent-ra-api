#include "KeyContainer.h"

#include <cstring>

#include <exception>

#include "../Common.h"
#include "../make_unique.h"
#include "../MbedTls/MbedTlsObjects.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

using namespace Decent::MbedTlsObj;
using namespace Decent::Ra;
using namespace Decent;

namespace
{
	static std::unique_ptr<ECKeyPair> CosntructKeyPair(const std::shared_ptr<const general_secp256r1_public_t>& pub, const std::shared_ptr<const PrivateKeyWrap>& prv)
	{
		std::unique_ptr<ECKeyPair> keyPair;
		if (pub && prv)
		{
			keyPair = Tools::make_unique<ECKeyPair>(ECKeyPair::FromGeneral(prv->m_prvKey, *pub));
		}

		if (!keyPair || !*keyPair)
		{
			LOGW("Failed to create new key pair!");
			throw std::runtime_error("Failed to create new key pair!"); //If error happened, this should be thrown at the program startup.
		}

		return std::move(keyPair);
	}
}

KeyContainer::KeyContainer(std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > keyPair) :
	m_signPubKey(std::move(keyPair.first)),
	m_signPrvKey(std::move(keyPair.second)),
	m_signPrvKeyObj(std::move(CosntructKeyPair(m_signPubKey, m_signPrvKey)))
{
}

KeyContainer::KeyContainer(std::unique_ptr<ECKeyPair> keyPair) :
	m_signPubKey(std::make_shared<general_secp256r1_public_t>(keyPair->ToGeneralPubKeyChecked())),
	m_signPrvKey(std::make_shared<PrivateKeyWrap>(keyPair->ToGeneralPrvKeyChecked())),
	m_signPrvKeyObj(std::move(keyPair))
{
}

KeyContainer::~KeyContainer()
{
}

std::shared_ptr<const PrivateKeyWrap> KeyContainer::GetSignPrvKey() const
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

std::shared_ptr<const ECKeyPair> KeyContainer::GetSignKeyPair() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_signPrvKeyObj);
#else
	return m_signPrvKeyObj;
#endif // DECENT_THREAD_SAFETY_HIGH
}
