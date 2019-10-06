#pragma once

#include "../MbedTls/X509Cert.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class EcKeyPairBase;
		class EcPublicKeyBase;
	}

	namespace Ra
	{
		/**
		 * \brief	Get the default X509 verify profile used by DECENT RA (i.e. NSA suit B).
		 *
		 * \return	The X509 verify profile.
		 */
		const mbedtls_x509_crt_profile& GetX509Profile();

		class ServerX509CertWriter : public MbedTlsObj::X509CertWriter
		{
		public:

			ServerX509CertWriter() = delete;

			/**
			 * \brief	Constructs DECENT Server certificate, a self-signed certificate.
			 *
			 * \param	prvKey			The key pair including private key.
			 * \param	enclaveHash 	The hash of the enclave.
			 * \param	platformType	Type of the platform.
			 * \param	selfRaReport	The self RA report.
			 */
			ServerX509CertWriter(MbedTlsObj::EcKeyPairBase& prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport);

			/** \brief	Destructor */
			virtual ~ServerX509CertWriter();
		};

		class ServerX509Cert : public MbedTlsObj::X509Cert
		{
		public:

			ServerX509Cert() = delete;

			ServerX509Cert(const ServerX509Cert& rhs) = delete;

			ServerX509Cert(ServerX509Cert&& rhs);

			ServerX509Cert(const std::vector<uint8_t>& der);

			ServerX509Cert(const std::string& ref);

			ServerX509Cert(mbedtls_x509_crt& cert);

			virtual ~ServerX509Cert();

			virtual ServerX509Cert& operator=(const ServerX509Cert& other) = delete;

			virtual ServerX509Cert& operator=(ServerX509Cert&& other);

			/**
			 * \brief	Gets platform type of the DECENT server.
			 *
			 * \return	The platform type.
			 */
			const std::string& GetPlatformType() const;

			/**
			 * \brief	Gets self RA report embedded in the certificate.
			 *
			 * \return	The self RA report.
			 */
			const std::string& GetSelfRaReport() const;

		private:

			void ParseExtensions();

			std::string m_platformType;
			std::string m_selfRaReport;
		};
	}
}
