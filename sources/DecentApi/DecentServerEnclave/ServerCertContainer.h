#pragma once

#include "../Common/Ra/CertContainer.h"

namespace Decent
{
	namespace Ra
	{
		class ServerX509Cert;

		class ServerCertContainer : public CertContainer
		{
		public:
			ServerCertContainer() noexcept;
			virtual ~ServerCertContainer() noexcept;

			std::shared_ptr<const ServerX509Cert> GetServerCert() const noexcept;

			bool SetServerCert(std::shared_ptr<const ServerX509Cert> cert) noexcept;

		private:
			std::shared_ptr<const ServerX509Cert> m_cert;
		};
	}
}
