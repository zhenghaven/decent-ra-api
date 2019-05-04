#pragma once

#include "../TlsConfigWithName.h"

namespace Decent
{
	namespace Ra
	{
		namespace Verifier
		{
			class AppX509;

			class TlsConfig : public Decent::Ra::TlsConfigWithName
			{
			public:
				TlsConfig(Decent::Ra::States& state, Mode cntMode, const std::string& expectedVerifierName, const std::string & expectedAppName, std::shared_ptr<MbedTlsObj::SessionTicketMgrBase> ticketMgr);

				TlsConfig(Decent::Ra::Verifier::TlsConfig&& other);

				TlsConfig(const Decent::Ra::Verifier::TlsConfig& other) = delete;

				virtual ~TlsConfig();

				virtual Decent::Ra::Verifier::TlsConfig& operator=(const Decent::Ra::Verifier::TlsConfig& other) = delete;

				virtual Decent::Ra::Verifier::TlsConfig& operator=(Decent::Ra::Verifier::TlsConfig&& other) = delete;

				const std::string& GetExpectedVerifiedAppName() { return m_expectedVerifiedAppName; }

			protected:
				virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override;

				virtual int VerifyDecentAppCert(const Decent::Ra::AppX509& cert, int depth, uint32_t& flag) const override;
				virtual int VerifyDecentVerifiedAppCert(const Decent::Ra::Verifier::AppX509& cert, int depth, uint32_t& flag) const;

			private:
				std::string m_expectedVerifiedAppName;
			};
		}

	}
}
