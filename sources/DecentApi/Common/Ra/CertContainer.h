#pragma once

#include <memory>

namespace Decent
{
	namespace MbedTlsObj
	{
		class X509Cert;
	}

	namespace Ra
	{
		class CertContainer
		{
		public:
			CertContainer() noexcept;
			virtual ~CertContainer() noexcept;

			std::shared_ptr<const MbedTlsObj::X509Cert> GetCert() const noexcept;

			bool SetCert(std::shared_ptr<const MbedTlsObj::X509Cert> cert) noexcept;

		private:
			std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
		};
	}
}
