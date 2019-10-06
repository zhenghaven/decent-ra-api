#pragma once

#include "AppX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		class ClientX509CertWriter : public AppX509CertWriter
		{
		public:

			ClientX509CertWriter() = delete;

			/**
			 * \brief	Constructs a client certificate, issued by DECENT app, after the user is registered
			 * 			with the DECENT app. The client certificate in real world may have much more
			 * 			requirements, here is just an example used for experiment purpose only.
			 *
			 * \param [in,out]	pubKey   	The client's public key.
			 * \param 		  	appCert  	The DECENT App's certificate.
			 * \param [in,out]	appPrvKey	The DECENT App's key pair including the private key.
			 * \param 		  	userName 	The client's user name.
			 * \param 		  	identity 	The client's identity.
			 */
			ClientX509CertWriter(MbedTlsObj::EcPublicKeyBase& pubKey, const AppX509Cert& appCert, MbedTlsObj::EcKeyPairBase& appPrvKey,
				const std::string& userName, const std::string& identity);

			/** \brief	Destructor */
			virtual ~ClientX509CertWriter();
		};

		class ClientX509Cert : public AppX509Cert
		{
		public:
			ClientX509Cert() = delete;

			ClientX509Cert(const ClientX509Cert& rhs) = delete;

			ClientX509Cert(ClientX509Cert&& rhs);

			ClientX509Cert(const std::vector<uint8_t> & der);

			ClientX509Cert(const std::string & pem);

			ClientX509Cert(mbedtls_x509_crt& ref);

			virtual ~ClientX509Cert();

			virtual ClientX509Cert& operator=(ClientX509Cert&& rhs);
		};
	}
}
