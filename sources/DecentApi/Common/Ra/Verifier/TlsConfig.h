#pragma once

#include "../TlsConfig.h"

namespace Decent
{
	namespace Ra
	{
		namespace Verifier
		{
			class AppX509;

			class TlsConfig : public Decent::Ra::TlsConfig
			{
			public:
				TlsConfig(const std::string& expectedAppName, const std::string& expectedVerifierName, bool isServer);

				TlsConfig(Decent::Ra::Verifier::TlsConfig&& other);
				TlsConfig(const Decent::Ra::Verifier::TlsConfig& other) = delete;

				virtual ~TlsConfig() {}

				virtual Decent::Ra::Verifier::TlsConfig& operator=(const Decent::Ra::Verifier::TlsConfig& other) = delete;
				virtual Decent::Ra::Verifier::TlsConfig& operator=(Decent::Ra::Verifier::TlsConfig&& other);

				const std::string& GetExpectedVerifiedAppName() { return m_expectedVerifiedAppName; }

			protected:
				virtual int CertVerifyCallBack(mbedtls_x509_crt* cert, int depth, uint32_t* flag) const override;
				virtual int AppCertVerifyCallBack(const Decent::Ra::AppX509& cert, int depth, uint32_t& flag) const override;
				virtual int AppCertVerifyCallBack(const Decent::Ra::Verifier::AppX509& cert, int depth, uint32_t& flag) const;

			private:
				std::string m_expectedVerifiedAppName;
			};
		}

	}
}
