#pragma once

#include "../MbedTls/MbedTlsObjects.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509;
		class ServerX509;
		class States;

		class TlsConfig : public MbedTlsObj::TlsConfig
		{
		public:
			TlsConfig(const std::string& expectedAppName, States& state, bool isServer);
			TlsConfig(const std::string& expectedAppName, States& state);

			TlsConfig(TlsConfig&& other);
			TlsConfig(const TlsConfig& other) = delete;
			virtual ~TlsConfig() {}

			virtual TlsConfig& operator=(const TlsConfig& other) = delete;
			virtual TlsConfig& operator=(TlsConfig&& other);

			virtual operator bool() const noexcept override
			{
				return MbedTlsObj::TlsConfig::operator bool() && m_isValid;
			}

			const std::string& GetExpectedAppName() const { return m_expectedAppName; }

			States& GetState() const { return m_state; }

			static int CertVerifyCallBack(void* inst, mbedtls_x509_crt* cert, int depth, uint32_t* flag);

		protected:
			virtual int CertVerifyCallBack(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const;
			virtual int AppCertVerifyCallBack(const AppX509& cert, int depth, uint32_t& flag) const;
			virtual int ServerCertVerifyCallBack(const ServerX509& cert, int depth, uint32_t& flag) const;

		private:
			States& m_state;
			std::shared_ptr<const MbedTlsObj::ECKeyPair> m_prvKey;
			std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
			std::string m_expectedAppName;

			bool m_isValid;
		};
	}
}
