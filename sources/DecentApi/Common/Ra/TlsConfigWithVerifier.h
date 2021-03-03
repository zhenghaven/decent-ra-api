#pragma once

#include "TlsConfigWithName.h"

#include "VerifiedAppX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		class TlsConfigWithVerifier : public TlsConfigWithName
		{
		public: // Static members:

			using _Base = TlsConfigWithName;

		public:
			TlsConfigWithVerifier() = delete;

			TlsConfigWithVerifier(States& state,
				bool isServer, bool vrfyPeer,
				const std::string& expectedVerifierName,
				const std::string & expectedAppName,
				std::shared_ptr<mbedTLScpp::TlsSessTktMgrIntf> ticketMgr) :
				_Base::TlsConfigWithName(state,
					isServer, vrfyPeer,
					expectedVerifierName,
					ticketMgr),
				m_expectedVerifiedAppName(expectedAppName)
			{}

			TlsConfigWithVerifier(TlsConfigWithVerifier&& other) :
				_Base::TlsConfigWithName(std::forward<_Base>(other)),
				m_expectedVerifiedAppName(std::move(other.m_expectedVerifiedAppName))
			{}

			TlsConfigWithVerifier(const TlsConfigWithVerifier& other) = delete;

			virtual ~TlsConfigWithVerifier()
			{}

			TlsConfigWithVerifier& operator=(TlsConfigWithVerifier&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs));

				if (this != &rhs)
				{
					m_expectedVerifiedAppName = std::move(m_expectedVerifiedAppName);
				}

				return *this;
			}

			TlsConfigWithVerifier& operator=(const TlsConfigWithVerifier& other) = delete;

			const std::string& GetExpectedVerifiedAppName()
			{
				return m_expectedVerifiedAppName;
			}

		protected:
			virtual int CustomVerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override
			{
				using namespace mbedTLScpp;

				switch (depth)
				{
				case 0: //Decent App Cert
				{
					VerifiedAppX509CertBase<BorrowedX509CertTrait> appCert(&cert);

					return VerifyDecentVerifiedAppCert(appCert, depth, flag);
				}
				case 1: //Decent Verifier Cert
				{
					const AppX509CertBase<BorrowedX509CertTrait> verifierCert(&cert);

					return VerifyDecentAppCert(verifierCert, depth, flag);
				}
				case 2: //Decent Server Cert
				{
					const ServerX509CertBase<BorrowedX509CertTrait> serverCert(&cert);

					return VerifyDecentServerCert(serverCert, depth, flag);
				}
				default:
					return MBEDTLS_ERR_X509_FATAL_ERROR;
				}
			}

			virtual int VerifyDecentAppCert(
				const AppX509CertBase<mbedTLScpp::BorrowedX509CertTrait>& cert,
				int depth, uint32_t& flag) const override
			{
				using namespace Decent::Ra::WhiteList;

				if (flag != 0x00)
				{
					//Decent Server cert is invalid! Directly return.
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check peer's hash is in the white list, and the app name is matched.
				std::string peerHash = GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
				if (!GetState().GetLoadedWhiteList().CheckHashAndName(peerHash, GetExpectedAppName()))
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check Loaded Lists are equivalent
				StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
				if (peerLoadedList <= GetState().GetLoadedWhiteList())
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				return MBEDTLS_EXIT_SUCCESS;
			}

			virtual int VerifyDecentVerifiedAppCert(
				const VerifiedAppX509CertBase<mbedTLScpp::BorrowedX509CertTrait>& cert,
				int depth, uint32_t& flag) const
			{
				using namespace Decent::Ra::WhiteList;

				if (flag != 0x00)
				{
					//Verifier cert is invalid! Directly return.
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check Loaded Lists are equivalent
				StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
				if (GetState().GetLoadedWhiteList() != peerLoadedList)
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check peer's common name is same as expected.
				if (cert.GetCommonName() != m_expectedVerifiedAppName)
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				return MBEDTLS_EXIT_SUCCESS;
			}

		private:
			std::string m_expectedVerifiedAppName;
		};

	}
}
