#include "KeyContainer.h"

#include <cstring>

#include <exception>

#include "../CommonTool.h"
#include "../MbedTlsObjects.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

using namespace MbedTlsObj;
using namespace Decent;

namespace
{
	static std::unique_ptr<ECKeyPair> CosntructKeyPair(const std::unique_ptr<general_secp256r1_public_t>& pub, const std::unique_ptr<PrivateKeyWrap>& prv)
	{
		std::unique_ptr<ECKeyPair> keyPair;
		if (pub && prv)
		{
			keyPair = Common::make_unique<ECKeyPair>(prv->m_prvKey, *pub);
		}

		if (!keyPair || !*keyPair)
		{
			throw std::exception("Failed to create new key pair!"); //This should be thrown at the program startup.
		}

		return std::move(keyPair);
	}
}

KeyContainer::KeyContainer(std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > keyPair) :
	m_signPubKey(std::move(keyPair.first)),
	m_signPrvKey(std::move(keyPair.second)),
	m_signPrvKeyObj(CosntructKeyPair(keyPair.first, keyPair.second))
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
