#pragma once

#include <mbedTLScpp/X509Cert.hpp>
#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/BigNumber.hpp>

#include "../Common.h"
#include "../Exceptions.h"

#include "ServerX509Cert.h"

#include "Internal/Cert.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509CertWriter : public mbedTLScpp::X509CertWriter
		{
		public: // Static members:

			using _Base = mbedTLScpp::X509CertWriter;

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
			template<typename _AppPKObjTrait,
				typename _SvrCertTrait,
				typename _SvrPKObjTrait
			>
			AppX509CertWriter(
				const mbedTLScpp::EcPublicKeyBase<_AppPKObjTrait>& pubKey,
				const ServerX509CertBase<_SvrCertTrait>& svrCert,
				const mbedTLScpp::EcKeyPairBase<_SvrPKObjTrait>& svrPrvKey,
				const std::string& enclaveHash,
				const std::string& platformType,
				const std::string& appId,
				const std::string& whiteList) :
				X509CertWriter(
					_Base::CaSign(
						mbedTLScpp::HashType::SHA256, svrCert, svrPrvKey, pubKey, ("CN=" + enclaveHash)
					)
				)
			{
				_Base::SetBasicConstraints(true, -1);
				_Base::SetKeyUsage(
					MBEDTLS_X509_KU_NON_REPUDIATION |
					MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					MBEDTLS_X509_KU_KEY_AGREEMENT |
					MBEDTLS_X509_KU_KEY_CERT_SIGN |
					MBEDTLS_X509_KU_CRL_SIGN
				);
				_Base::SetNsType(
					MBEDTLS_X509_NS_CERT_TYPE_SSL_CA |
					MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
					MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER
				);

				_Base::SetSerialNum(mbedTLScpp::BigNum::Rand(GENERAL_256BIT_32BYTE_SIZE));

				_Base::SetV3Extensions(
					std::map<std::string, std::pair<bool, std::string> >
					{
						std::make_pair(detail::gsk_x509PlatformTypeOid, std::make_pair(false, platformType)),
						std::make_pair(detail::gsk_x509LaIdOid,         std::make_pair(false, appId)),
						std::make_pair(detail::gsk_x509WhiteListOid,    std::make_pair(false, whiteList)),
					}
				);

				time_t timerBegin;
				Tools::GetSystemTime(timerBegin);
				time_t timerEnd = timerBegin + detail::gsk_x509ValidTime;

				std::tm timerBeginSt;
				std::tm timerEndSt;
				Tools::GetSystemUtcTime(timerBegin, timerBeginSt);
				Tools::GetSystemUtcTime(timerEnd, timerEndSt);

				_Base::SetValidationTime(
					detail::X509FormatTime(timerBeginSt), detail::X509FormatTime(timerEndSt));
			}

			/** \brief	Destructor */
			virtual ~AppX509CertWriter()
			{}
		};

		template<typename _X509CertObjTrait = mbedTLScpp::DefaultX509CertObjTrait,
			mbedTLScpp::enable_if_t<
				std::is_same<typename _X509CertObjTrait::CObjType, mbedtls_x509_crt>::value, int
			> = 0>
		class AppX509CertBase : public mbedTLScpp::X509CertBase<_X509CertObjTrait>
		{
		public: // Static members:

			using CertTrait = _X509CertObjTrait;
			using _Base     = mbedTLScpp::X509CertBase<CertTrait>;

			static AppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromPEM(const std::string& pem)
			{
				return AppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromPEM(pem));
			}

			template<typename _SecCtnType>
			static AppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromDER(const mbedTLScpp::ContCtnReadOnlyRef<_SecCtnType, false>& der)
			{
				return AppX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromDER(der));
			}

		public:
			AppX509CertBase() = delete;

			template<typename _dummy_CertTrait = CertTrait,
				mbedTLScpp::enable_if_t<_dummy_CertTrait::sk_isBorrower, int> = 0>
			AppX509CertBase(mbedtls_x509_crt * other) :
				_Base::X509CertBase(other),
				m_platformType(),
				m_appId(),
				m_whiteList()
			{
				ParseExtensions();
			}

			AppX509CertBase(const AppX509CertBase& rhs) = delete;

			AppX509CertBase(AppX509CertBase&& other) :
				_Base::X509CertBase(std::forward<_Base>(other)),
				m_platformType(std::move(other.m_platformType)),
				m_appId(std::move(other.m_appId)),
				m_whiteList(std::move(other.m_whiteList))
			{}

			virtual ~AppX509CertBase()
			{}

			AppX509CertBase& operator=(const AppX509CertBase& rhs) = delete;

			AppX509CertBase& operator=(AppX509CertBase&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs));
				if (this != &rhs)
				{
					m_platformType = std::move(rhs.m_platformType);
					m_appId        = std::move(rhs.m_appId);
					m_whiteList    = std::move(rhs.m_whiteList);
				}
				return *this;
			}

			const std::string& GetPlatformType() const
			{
				return m_platformType;
			}

			const std::string& GetAppId() const
			{
				return m_appId;
			}

			const std::string& GetWhiteList() const
			{
				return m_whiteList;
			}

		protected:

			template<typename _dummy_CertTrait = CertTrait,
				mbedTLScpp::enable_if_t<!_dummy_CertTrait::sk_isBorrower, int> = 0>
			AppX509CertBase(_Base&& other) :
				_Base::X509CertBase(std::forward<_Base>(other)),
				m_platformType(),
				m_appId(),
				m_whiteList()
			{
				ParseExtensions();
			}

		private:

			void ParseExtensions()
			{
				auto extMap = _Base::GetV3Extensions();

				auto it = extMap.find(detail::gsk_x509PlatformTypeOid);
				if (it == extMap.end())
				{
					throw RuntimeException("AppX509CertBase::ParseExtensions - Invalid certificate. Platform Type field is missing.");
				}

				m_platformType = std::move(it->second.second);

				it = extMap.find(detail::gsk_x509LaIdOid);
				if (it == extMap.end())
				{
					throw RuntimeException("AppX509CertBase::ParseExtensions - Invalid certificate. LA ID field is missing.");
				}
				m_appId = std::move(it->second.second);

				it = extMap.find(detail::gsk_x509WhiteListOid);
				if (it == extMap.end())
				{
					throw RuntimeException("AppX509CertBase::ParseExtensions - Invalid certificate. Whitelist field is missing.");
				}
				m_whiteList = std::move(it->second.second);
			}

			std::string m_platformType;
			std::string m_appId;
			std::string m_whiteList;
		};

		using AppX509Cert = AppX509CertBase<>;
	}
}
