#pragma once

#include "../MbedTls/MbedTlsObjects.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509;
		class ServerX509;

		class TlsConfig : public MbedTlsObj::TlsConfig
		{
		public:
			TlsConfig(const std::string& expectedAppName, bool isServer);

			TlsConfig(TlsConfig&& other);
			TlsConfig(const TlsConfig& other) = delete;
			virtual ~TlsConfig() {}

			virtual TlsConfig& operator=(const TlsConfig& other) = delete;
			virtual TlsConfig& operator=(TlsConfig&& other);

			virtual void Destroy() override;

			const std::string& GetExpectedAppName() const { return m_expectedAppName; }

		protected:
			TlsConfig(mbedtls_ssl_config* ptr);
			virtual int CertVerifyCallBack(mbedtls_x509_crt* cert, int depth, uint32_t* flag) const;
			virtual int AppCertVerifyCallBack(const AppX509& cert, int depth, uint32_t& flag) const;
			virtual int ServerCertVerifyCallBack(const ServerX509& cert, int depth, uint32_t& flag) const;

		private:
			static int CertVerifyCallBack(void* inst, mbedtls_x509_crt* cert, int depth, uint32_t* flag);

			std::shared_ptr<const MbedTlsObj::ECKeyPair> m_prvKey;
			std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
			std::string m_expectedAppName;
		};
	}
}
