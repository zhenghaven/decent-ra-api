#pragma once

#include "../Common/Ra/CertContainer.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509;

		class AppCertContainer : public CertContainer
		{
		public:
			AppCertContainer() noexcept;
			virtual ~AppCertContainer() noexcept;

			std::shared_ptr<const AppX509> GetAppCert() const noexcept;

			bool SetAppCert(std::shared_ptr<const AppX509> cert) noexcept;

		private:
			std::shared_ptr<const AppX509> m_cert;
		};
	}
}
