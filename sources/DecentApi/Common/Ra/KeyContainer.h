#pragma once

#include <memory>
#include <string>

#include "../GeneralKeyTypes.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class ECKeyPair;
	}

	namespace Ra
	{
		class KeyContainer
		{
		public:
			KeyContainer();

			virtual ~KeyContainer();

			virtual std::shared_ptr<const PrivateKeyWrap> GetSignPrvKey() const;

			virtual std::shared_ptr<const general_secp256r1_public_t> GetSignPubKey() const;

			virtual std::shared_ptr<const MbedTlsObj::ECKeyPair> GetSignKeyPair() const;

		protected:
			KeyContainer(std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > keyPair);
			KeyContainer(std::unique_ptr<MbedTlsObj::ECKeyPair> keyPair);

			virtual void SetSignPrvKey(std::shared_ptr<const PrivateKeyWrap> key);

			virtual void SetSignPubKey(std::shared_ptr<const general_secp256r1_public_t> key);

			virtual void SetSignKeyPair(std::shared_ptr<const MbedTlsObj::ECKeyPair> key);

		private:
			std::shared_ptr<const general_secp256r1_public_t> m_signPubKey;
			std::shared_ptr<const PrivateKeyWrap> m_signPrvKey;
			std::shared_ptr<const MbedTlsObj::ECKeyPair> m_signPrvKeyObj;
		};
	}
}

