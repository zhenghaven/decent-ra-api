#pragma once

#include "../Common/Ra/CertContainer.h"

namespace Decent
{
	namespace Ra
	{
		class ServerX509;

		class ServerCertContainer : public CertContainer
		{
		public:
			ServerCertContainer() noexcept;
			virtual ~ServerCertContainer() noexcept;

			std::shared_ptr<const ServerX509> GetServerCert() const noexcept;

			bool SetServerCert(std::shared_ptr<const ServerX509> cert) noexcept;

		private:
			std::shared_ptr<const ServerX509> m_cert;
		};
	}
}
