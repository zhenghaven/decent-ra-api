#pragma once

#include "AppX509Cert.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class EcPublicKeyBase;
	}

	namespace Ra
	{
		class VerifiedAppX509CertWriter : public AppX509CertWriter
		{
		public:

			VerifiedAppX509CertWriter() = delete;

			/**
			 * \brief	Issue a certificate to a verified (not directly listed in the whitelist) DECENT App.
			 *
			 * \param 		  	oriCert		  	The original DECENT App certificate issued by the DECENT
			 * 									Server.
			 * \param 		  	verifierCert  	The DECENT Verifier's certificate.
			 * \param [in,out]	verifierPrvKey	The DECENT Verifier's key pair including the private key.
			 * \param 		  	appName		  	The name of the DECENT App.
			 */
			VerifiedAppX509CertWriter(const AppX509Cert& oriCert, const AppX509Cert& verifierCert, MbedTlsObj::EcKeyPairBase& verifierPrvKey,
				const std::string& appName);

			/**
			 * \brief	Issue a certificate to a verified (not directly listed in the whitelist) DECENT App.
			 *
			 * \param 		  	oriCert		  	The original DECENT App certificate issued by the DECENT
			 * 									Server.
			 * \param 		  	pubKey		  	The DECENT App's public key.
			 * \param 		  	verifierCert  	The DECENT Verifier's certificate.
			 * \param [in,out]	verifierPrvKey	The DECENT Verifier's key pair including the private key.
			 * \param 		  	appName		  	The name of the DECENT App.
			 */
			VerifiedAppX509CertWriter(const AppX509Cert& oriCert, MbedTlsObj::EcPublicKeyBase pubKey, const AppX509Cert& verifierCert, MbedTlsObj::EcKeyPairBase& verifierPrvKey,
				const std::string& appName);

			/** \brief	Destructor */
			virtual ~VerifiedAppX509CertWriter();
		};

		class VerifiedAppX509Cert : public AppX509Cert
		{
		public:
			VerifiedAppX509Cert() = delete;

			VerifiedAppX509Cert(VerifiedAppX509Cert&& rhs);

			VerifiedAppX509Cert(const VerifiedAppX509Cert& rhs) = delete;

			VerifiedAppX509Cert(const std::vector<uint8_t> & der);

			VerifiedAppX509Cert(const std::string & pem);

			VerifiedAppX509Cert(mbedtls_x509_crt& ref);

			virtual ~VerifiedAppX509Cert() {}

			virtual VerifiedAppX509Cert& operator=(VerifiedAppX509Cert&& rhs);
		};

	}
}
