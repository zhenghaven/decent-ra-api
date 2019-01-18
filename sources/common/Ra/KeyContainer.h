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

		private:
			std::shared_ptr<const general_secp256r1_public_t> m_signPubKey;
			std::shared_ptr<const PrivateKeyWrap> m_signPrvKey;
			std::shared_ptr<const MbedTlsObj::ECKeyPair> m_signPrvKeyObj;
		};
	}
}

