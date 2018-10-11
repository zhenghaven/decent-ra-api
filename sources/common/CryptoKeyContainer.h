#pragma once

#include <memory>
#include <string>

#include "GeneralKeyTypes.h"

namespace MbedTlsObj
{
	class ECKeyPublic;
	class ECKeyPair;
}

class CryptoKeyContainer
{
public:
	static CryptoKeyContainer& GetInstance();

	CryptoKeyContainer();

	virtual ~CryptoKeyContainer();

	virtual operator bool() const;

	virtual std::shared_ptr<const PrivateKeyWrap> GetSignPrvKey() const;

	virtual std::shared_ptr<const general_secp256r1_public_t> GetSignPubKey() const;

	virtual std::shared_ptr<const MbedTlsObj::ECKeyPair> GetSignKeyPair() const;

	virtual bool UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const general_secp256r1_public_t> pub);

	virtual bool UpdateSignKeyPair(std::shared_ptr<const MbedTlsObj::ECKeyPair> keyPair);

private:
	CryptoKeyContainer(const std::pair<general_secp256r1_public_t*, PrivateKeyWrap*>& keyPair);
	CryptoKeyContainer(MbedTlsObj::ECKeyPair* keyPair);
	CryptoKeyContainer(general_secp256r1_public_t* pubKey, PrivateKeyWrap* prvKey, MbedTlsObj::ECKeyPair* keyPair);

	std::shared_ptr<const general_secp256r1_public_t> m_signPubKey;

	std::shared_ptr<const PrivateKeyWrap> m_signPrvKey;

	std::shared_ptr<const MbedTlsObj::ECKeyPair> m_signPrvKeyObj;

	const bool k_isValid;
};

