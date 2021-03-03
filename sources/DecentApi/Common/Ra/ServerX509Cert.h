#pragma once

#include <mbedTLScpp/X509Cert.hpp>
#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/BigNumber.hpp>

#include "../Common.h"
#include "../Exceptions.h"

#include "Internal/Cert.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	Get the default X509 verify profile used by DECENT RA (i.e. NSA suit B).
		 *
		 * \return	The X509 verify profile.
		 */
		inline const mbedtls_x509_crt_profile& GetX509Profile()
		{
			return mbedtls_x509_crt_profile_suiteb;
		}

		class ServerX509CertWriter : public mbedTLScpp::X509CertWriter
		{
		public: // Static members:

			using _Base = mbedTLScpp::X509CertWriter;

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
			template<typename _PKObjTrait>
			ServerX509CertWriter(const mbedTLScpp::EcKeyPairBase<_PKObjTrait>& prvKey,
				const std::string& enclaveHash,
				const std::string& platformType,
				const std::string& selfRaReport) :
				_Base::X509CertWriter(
					_Base::SelfSign(
						mbedTLScpp::HashType::SHA256, prvKey, ("CN=" + enclaveHash)
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
				_Base::SetSerialNum(mbedTLScpp::BigNum::Rand(sizeof(uint32_t) * mbedTLScpp::gsk_bitsPerByte));

				_Base::SetV3Extensions(
					std::map<std::string, std::pair<bool, std::string> >
					{
						std::make_pair(detail::gsk_x509PlatformTypeOid, std::make_pair(false, platformType)),
						std::make_pair(detail::gsk_x509SelfRaReportOid, std::make_pair(false, selfRaReport)),
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
			virtual ~ServerX509CertWriter()
			{}
		};

		template<typename _X509CertObjTrait = mbedTLScpp::DefaultX509CertObjTrait,
			mbedTLScpp::enable_if_t<
				std::is_same<typename _X509CertObjTrait::CObjType, mbedtls_x509_crt>::value, int
			> = 0>
		class ServerX509CertBase : public mbedTLScpp::X509CertBase<_X509CertObjTrait>
		{
		public: // Static members:

			using CertTrait = _X509CertObjTrait;
			using _Base     = mbedTLScpp::X509CertBase<CertTrait>;

			static ServerX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromPEM(const std::string& pem)
			{
				return ServerX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromPEM(pem));
			}

			template<typename _SecCtnType>
			static ServerX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>
				FromDER(const mbedTLScpp::ContCtnReadOnlyRef<_SecCtnType, false>& der)
			{
				return ServerX509CertBase<mbedTLScpp::DefaultX509CertObjTrait>(_Base::FromDER(der));
			}

		public:

			ServerX509CertBase() = delete;

			template<typename _dummy_CertTrait = CertTrait,
				mbedTLScpp::enable_if_t<_dummy_CertTrait::sk_isBorrower, int> = 0>
			ServerX509CertBase(mbedtls_x509_crt* other) :
				_Base::X509CertBase(other),
				m_platformType(),
				m_selfRaReport()
			{
				ParseExtensions();
			}

			//ServerX509CertBase(const ServerX509CertBase& other) :
			//	_Base::X509CertBase(_Base::FromDER(mbedTLScpp::CtnFullR(other.GetDer()))),
			//	m_platformType(other.m_platformType),
			//	m_selfRaReport(other.m_selfRaReport)
			//{}

			ServerX509CertBase(ServerX509CertBase&& other) :
				_Base::X509CertBase(std::forward<_Base>(other)),
				m_platformType(std::move(other.m_platformType)),
				m_selfRaReport(std::move(other.m_selfRaReport))
			{}

			virtual ~ServerX509CertBase()
			{}

			ServerX509CertBase& operator=(const ServerX509CertBase& rhs) = delete;

			ServerX509CertBase& operator=(ServerX509CertBase&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs));
				if (this != &rhs)
				{
					m_platformType = std::move(rhs.m_platformType);
					m_selfRaReport = std::move(rhs.m_selfRaReport);
				}
				return *this;
			}

			/**
			 * \brief	Gets platform type of the DECENT server.
			 *
			 * \return	The platform type.
			 */
			const std::string& GetPlatformType() const
			{
				return m_platformType;
			}

			/**
			 * \brief	Gets self RA report embedded in the certificate.
			 *
			 * \return	The self RA report.
			 */
			const std::string& GetSelfRaReport() const
			{
				return m_selfRaReport;
			}

		protected:

			template<typename _dummy_CertTrait = CertTrait,
				mbedTLScpp::enable_if_t<!_dummy_CertTrait::sk_isBorrower, int> = 0>
			ServerX509CertBase(_Base&& other) :
				_Base::X509CertBase(std::forward<_Base>(other)),
				m_platformType(),
				m_selfRaReport()
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
					throw RuntimeException("ServerX509CertBase::ParseExtensions - Invalid certificate; Platform Type field is missing.");
				}

				m_platformType = std::move(it->second.second);

				it = extMap.find(detail::gsk_x509SelfRaReportOid);
				if (it == extMap.end())
				{
					throw RuntimeException("ServerX509CertBase::ParseExtensions - Invalid certificate; Self RA Report field is missing.");
				}
				m_selfRaReport = std::move(it->second.second);
			}

			std::string m_platformType;
			std::string m_selfRaReport;
		};

		using ServerX509Cert = ServerX509CertBase<>;
	}
}
