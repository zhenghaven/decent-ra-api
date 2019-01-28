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
				AppX509(const std::string & pemStr);
				AppX509(mbedtls_x509_crt* cert);
				AppX509(const Decent::Ra::AppX509& oriCert,
					const Decent::Ra::AppX509& verifierCert, const Decent::MbedTlsObj::ECKeyPair& verifierPrvKey,
					const std::string& appName);
				AppX509(const AppX509& other) = delete;
				virtual ~AppX509() {}

			};
		}

	}
}
