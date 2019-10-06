#pragma once

#include "TlsConfigWithName.h"

namespace Decent
{
	namespace Ra
	{
		class VerifiedAppX509Cert;

		class TlsConfigWithVerifier : public TlsConfigWithName
		{
		public:
			TlsConfigWithVerifier() = delete;

			TlsConfigWithVerifier(TlsConfigWithVerifier&& other);

			TlsConfigWithVerifier(const TlsConfigWithVerifier& other) = delete;

			TlsConfigWithVerifier(States& state, Mode cntMode, const std::string& expectedVerifierName, const std::string & expectedAppName, std::shared_ptr<MbedTlsObj::SessionTicketMgrBase> ticketMgr);

			virtual ~TlsConfigWithVerifier();

			virtual TlsConfigWithVerifier& operator=(const TlsConfigWithVerifier& other) = delete;

			virtual TlsConfigWithVerifier& operator=(TlsConfigWithVerifier&& other) = delete;

			const std::string& GetExpectedVerifiedAppName() { return m_expectedVerifiedAppName; }

		protected:
			virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override;

			virtual int VerifyDecentAppCert(const AppX509Cert& cert, int depth, uint32_t& flag) const override;

			virtual int VerifyDecentVerifiedAppCert(const VerifiedAppX509Cert& cert, int depth, uint32_t& flag) const;

		private:
			std::string m_expectedVerifiedAppName;
		};

	}
}
