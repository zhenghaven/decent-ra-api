#pragma once

#include "../Common/Ra/CertContainer.h"

#include "../Common/Ra/ServerX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		class ServerCertContainer : public CertContainer
		{
		public:
			ServerCertContainer() :
				CertContainer(),
				m_cert()
			{}

			virtual ~ServerCertContainer()
			{}

			std::shared_ptr<const ServerX509Cert> GetServerCert() const
			{
				return CertContainer::DataGetter(m_cert);
			}

			void SetServerCert(std::shared_ptr<const ServerX509Cert> cert)
			{
				CertContainer::SetCert(cert);

				CertContainer::DataSetter(m_cert, cert);
			}

		private:
			std::shared_ptr<const ServerX509Cert> m_cert;
		};
	}
}
