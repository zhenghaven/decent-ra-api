#pragma once

#include "../Common/Ra/CertContainer.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509Cert;

		class AppCertContainer : public CertContainer
		{
		public:
			AppCertContainer() noexcept;
			virtual ~AppCertContainer() noexcept;

			std::shared_ptr<const AppX509Cert> GetAppCert() const noexcept;

			bool SetAppCert(std::shared_ptr<const AppX509Cert> cert) noexcept;

		private:
			std::shared_ptr<const AppX509Cert> m_cert;
		};
	}
}
