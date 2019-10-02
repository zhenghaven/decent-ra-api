#pragma once

#include <memory>
#include <string>

#include "../GeneralKeyTypes.h"
#include "../MbedTls/EcKey.h"

namespace Decent
{
	namespace Ra
	{
		class KeyContainer
		{
		public:
			KeyContainer();

			KeyContainer(std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > keyPair);

			KeyContainer(std::unique_ptr<MbedTlsObj::EcKeyPair<MbedTlsObj::EcKeyType::SECP256R1> > keyPair);

			virtual ~KeyContainer();

			virtual std::shared_ptr<const PrivateKeyWrap> GetSignPrvKey() const;

			virtual std::shared_ptr<const general_secp256r1_public_t> GetSignPubKey() const;

			virtual std::shared_ptr<const MbedTlsObj::EcKeyPair<MbedTlsObj::EcKeyType::SECP256R1> > GetSignKeyPair() const;

		protected:

			virtual void SetSignPrvKey(std::shared_ptr<const PrivateKeyWrap> key);

			virtual void SetSignPubKey(std::shared_ptr<const general_secp256r1_public_t> key);

			virtual void SetSignKeyPair(std::shared_ptr<const MbedTlsObj::EcKeyPair<MbedTlsObj::EcKeyType::SECP256R1> > key);

		private:
			std::shared_ptr<const general_secp256r1_public_t> m_signPubKey;
			std::shared_ptr<const PrivateKeyWrap> m_signPrvKey;
			std::shared_ptr<const MbedTlsObj::EcKeyPair<MbedTlsObj::EcKeyType::SECP256R1> > m_signPrvKeyObj;
		};
	}
}

