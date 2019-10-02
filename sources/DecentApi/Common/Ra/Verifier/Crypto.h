#pragma once

#include "../Crypto.h"

namespace Decent
{
	namespace Ra
	{
		namespace Verifier
		{
			class AppX509 : public Decent::Ra::AppX509
			{
			public:
				AppX509() = delete;

				AppX509(const std::string & pemStr) :
					Decent::Ra::AppX509(pemStr)
				{}

				AppX509(mbedtls_x509_crt& cert) : 
					Decent::Ra::AppX509(cert)
				{}

				AppX509(const Decent::Ra::AppX509& oriCert,
					const Decent::Ra::AppX509& verifierCert, const Decent::MbedTlsObj::EcKeyPairBase& verifierPrvKey,
					const std::string& appName);

				AppX509(AppX509&& other) :
					Decent::Ra::AppX509(std::forward<Decent::Ra::AppX509>(other))
				{}

				AppX509(const AppX509& other) = delete;

				virtual ~AppX509() {}

				virtual AppX509& operator=(AppX509&& other)
				{
					Decent::Ra::AppX509::operator=(std::forward<Decent::Ra::AppX509>(other));
					return *this;
				}
			};
		}

	}
}
