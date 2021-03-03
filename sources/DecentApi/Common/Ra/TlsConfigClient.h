#pragma once

#include "TlsConfigWithName.h"

#include "ClientX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		class TlsConfigClient : public TlsConfigWithName
		{
		public: // Static members:

			using _Base = TlsConfigWithName;

		public:
			TlsConfigClient(States& state,
				bool isServer, bool vrfyPeer,
				const std::string& expectedRegisterAppName,
				std::shared_ptr<mbedTLScpp::TlsSessTktMgrIntf> ticketMgr) :
				_Base::TlsConfigWithName(state,
					isServer, vrfyPeer,
					expectedRegisterAppName,
					ticketMgr)
			{}

			TlsConfigClient(TlsConfigClient&& other) :
				_Base::TlsConfigWithName(std::forward<_Base>(other))
			{}

			TlsConfigClient(const TlsConfigClient& other) = delete;

			virtual ~TlsConfigClient()
			{}

			TlsConfigClient& operator=(const TlsConfigClient& other) = delete;

			TlsConfigClient& operator=(TlsConfigClient&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs));

				return *this;
			}

		protected:
			virtual int CustomVerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override
			{
				using namespace mbedTLScpp;

				switch (depth)
				{
				case 0: //Client Cert
				{
					const ClientX509CertBase<BorrowedX509CertTrait> cltCert(&cert);

					return VerifyClientCert(cltCert, depth, flag);
				}
				case 1: //Decent App Cert
				{
					const AppX509CertBase<BorrowedX509CertTrait> appCert(&cert);

					return VerifyDecentAppCert(appCert, depth, flag);
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

			virtual int VerifyClientCert(
				const ClientX509CertBase<mbedTLScpp::BorrowedX509CertTrait>& cert,
				int depth, uint32_t& flag) const
			{
				//Currently we don't verify anything as long as the client's cert is signed by the expected Decent App.
				return MBEDTLS_EXIT_SUCCESS;
			}
		};
	}
}
