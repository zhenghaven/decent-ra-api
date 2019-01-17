#pragma once

#include <memory>

namespace MbedTlsObj
{
	class X509Cert;
}

namespace Decent
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
