#pragma once

#include "AppX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		class VerifiedAppX509CertWriter : public AppX509CertWriter
		{
		public: // Static members:

			using _Base = AppX509CertWriter;

		public:

			VerifiedAppX509CertWriter() = delete;

			/**
			 * \brief	Issue a certificate to a verified (not directly listed in the whitelist) DECENT App.
			 *
			 * \param 		  	oriCert		  	The original DECENT App certificate issued by the DECENT
			 *                                  Server.
			 * \param 		  	verifierCert  	The DECENT Verifier's certificate.
			 * \param [in,out]	verifierPrvKey	The DECENT Verifier's key pair including the private key.
			 * \param 		  	appName		  	The name of the DECENT App.
			 */
			template<typename _OriCertTrait,
				typename _VrfierCertTrait,
				typename _VrfierPkTrait
			>
			VerifiedAppX509CertWriter(const AppX509CertBase<_OriCertTrait>& oriCert,
				const AppX509CertBase<_VrfierCertTrait>& verifierCert,
				mbedTLScpp::EcKeyPairBase<_VrfierPkTrait>& verifierPrvKey,
				const std::string& appName) :
				_Base::AppX509CertWriter(
					oriCert.BorrowPublicKey(),
					verifierCert,
					verifierPrvKey,
					appName,
					oriCert.GetPlatformType(),
					oriCert.GetAppId(),
					oriCert.GetWhiteList()
				)
			{}

			/** \brief	Destructor */
			virtual ~VerifiedAppX509CertWriter()
			{}
		};

		template<typename _X509CertObjTrait = mbedTLScpp::DefaultX509CertObjTrait,
			mbedTLScpp::enable_if_t<
				std::is_same<typename _X509CertObjTrait::CObjType, mbedtls_x509_crt>::value, int
			> = 0>
		class VerifiedAppX509CertBase : public AppX509CertBase<_X509CertObjTrait>
		{
		public: // Static members:

			using CertTrait = _X509CertObjTrait;
			using _Base = AppX509CertBase<CertTrait>;

			static VerifiedAppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromPEM(const std::string& pem)
			{
				return VerifiedAppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromPEM(pem));
			}

			template<typename _SecCtnType>
			static VerifiedAppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromDER(const mbedTLScpp::ContCtnReadOnlyRef<_SecCtnType, false>& der)
			{
				return VerifiedAppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromDER(der));
			}

		public:
			VerifiedAppX509CertBase() = delete;

			template<typename _dummy_CertTrait = CertTrait,
				mbedTLScpp::enable_if_t<_dummy_CertTrait::sk_isBorrower, int> = 0>
			VerifiedAppX509CertBase(mbedtls_x509_crt* other) :
				_Base::AppX509CertBase(other)
			{}

			VerifiedAppX509CertBase(VerifiedAppX509CertBase&& rhs) :
				_Base::AppX509CertBase(std::forward<_Base>(other))
			{}

			VerifiedAppX509CertBase(const VerifiedAppX509CertBase& rhs) = delete;

			virtual ~VerifiedAppX509CertBase()
			{}

			VerifiedAppX509CertBase& operator=(const VerifiedAppX509CertBase& rhs) = delete;

			VerifiedAppX509CertBase& operator=(VerifiedAppX509CertBase&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs));
				return *this;
			}

		protected:

			template<typename _dummy_CertTrait = CertTrait,
				mbedTLScpp::enable_if_t<!_dummy_CertTrait::sk_isBorrower, int> = 0>
			VerifiedAppX509CertBase(_Base&& other) :
				_Base::AppX509CertBase(std::forward<_Base>(other))
			{}
		};

		using VerifiedAppX509Cert = VerifiedAppX509CertBase<>;
	}
}
