#pragma once

#include "AppX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		class ClientX509CertWriter : public AppX509CertWriter
		{
		public: // Static members:

			using _Base = AppX509CertWriter;

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
			template<typename _CltPKObjTrait,
				typename _AppCertTrait,
				typename _AppPKObjTrait
			>
			ClientX509CertWriter(
				const mbedTLScpp::EcPublicKeyBase<_CltPKObjTrait>& pubKey,
				const AppX509CertBase<_AppCertTrait>& appCert,
				const mbedTLScpp::EcKeyPairBase<_AppPKObjTrait>& appPrvKey,
				const std::string& userName,
				const std::string& identity) :
				_Base::AppX509CertWriter(pubKey, appCert, appPrvKey, userName, "DecentClient", identity, "{}")
			{}

			/** \brief	Destructor */
			virtual ~ClientX509CertWriter()
			{}
		};

		template<typename _X509CertObjTrait = mbedTLScpp::DefaultX509CertObjTrait,
			mbedTLScpp::enable_if_t<
				std::is_same<typename _X509CertObjTrait::CObjType, mbedtls_x509_crt>::value, int
			> = 0>
		class ClientX509CertBase : public AppX509CertBase<_X509CertObjTrait>
		{
		public: // Static members:

			using CertTrait = _X509CertObjTrait;
			using _Base     = AppX509CertBase<CertTrait>;

			static ClientX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromPEM(const std::string& pem)
			{
				return ClientX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromPEM(pem));
			}

			template<typename _SecCtnType>
			static ClientX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromDER(const mbedTLScpp::ContCtnReadOnlyRef<_SecCtnType, false>& der)
			{
				return ClientX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromDER(der));
			}

		public:

			using _Base::AppX509CertBase;

			ClientX509CertBase(ClientX509CertBase&& other) :
				_Base::AppX509CertBase(std::forward<_Base>(other))
			{}

			virtual ~ClientX509CertBase()
			{}

			ClientX509CertBase& operator=(ClientX509CertBase&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs));
				return *this;
			}
		};

		using ClientX509Cert = ClientX509CertBase<>;
	}
}
