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
			CertContainer();
			~CertContainer();

			std::shared_ptr<const MbedTlsObj::X509Cert> GetCert() const;

			bool SetCert(std::shared_ptr<const MbedTlsObj::X509Cert> cert);

		private:
			std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
		};
	}
}
