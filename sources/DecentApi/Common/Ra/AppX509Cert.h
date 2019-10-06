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
		class ServerX509Cert;

		/**
		 * \brief	Get the default X509 verify profile used by DECENT RA (i.e. NSA suit B).
		 *
		 * \return	The X509 verify profile.
		 */
		const mbedtls_x509_crt_profile& GetX509Profile();

		class AppX509CertWriter : public MbedTlsObj::X509CertWriter
		{
		public:

			AppX509CertWriter() = delete;

			/**
			 * \brief	Constructs DECENT App certificate, issued by DECENT Server.
			 *
			 * \param [in,out]	pubKey			The DECENT App's public key.
			 * \param 		  	svrCert			The DECENT Server's certificate.
			 * \param [in,out]	svrPrvKey   	The DECENT Server's key pair including the private key.
			 * \param 		  	enclaveHash 	The hash of the DECENT App enclave.
			 * \param 		  	platformType	Type of the platform.
			 * \param 		  	appId			The identity of the DECENT App.
			 * \param 		  	whiteList   	DECENT Whitelist.
			 */
			AppX509CertWriter(MbedTlsObj::EcPublicKeyBase& pubKey, const ServerX509Cert& svrCert, MbedTlsObj::EcKeyPairBase& svrPrvKey,
				const std::string& enclaveHash, const std::string& platformType, const std::string& appId, const std::string& whiteList);

			/** \brief	Destructor */
			virtual ~AppX509CertWriter();

		protected:

			AppX509CertWriter(MbedTlsObj::EcPublicKeyBase& pubKey, const MbedTlsObj::X509Cert& svrCert, MbedTlsObj::EcKeyPairBase& svrPrvKey,
				const std::string& enclaveHash, const std::string& platformType, const std::string& appId, const std::string& whiteList);
		};

		class AppX509Cert : public MbedTlsObj::X509Cert
		{
		public:
			AppX509Cert() = delete;

			AppX509Cert(const AppX509Cert& rhs) = delete;

			AppX509Cert(AppX509Cert&& other);

			AppX509Cert(const std::vector<uint8_t>& der);

			AppX509Cert(const std::string& pem);

			AppX509Cert(mbedtls_x509_crt& cert);

			virtual ~AppX509Cert();

			virtual AppX509Cert& operator=(const AppX509Cert& rhs) = delete;

			virtual AppX509Cert& operator=(AppX509Cert&& rhs);

			const std::string& GetPlatformType() const;

			const std::string& GetAppId() const;

			const std::string& GetWhiteList() const;

		private:

			void ParseExtensions();

			std::string m_platformType;
			std::string m_appId;
			std::string m_whiteList;
		};
	}
}
