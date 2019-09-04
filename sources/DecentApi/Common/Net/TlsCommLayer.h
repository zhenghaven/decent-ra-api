#pragma once

#include "SecureCommLayer.h"

#include <memory>

typedef struct mbedtls_ssl_context mbedtls_ssl_context;


namespace Decent
{
	namespace MbedTlsObj
	{
		class TlsConfig;
		class PKey;
		class X509Cert;
		class Session;
	}

	namespace Net
	{
		class TlsCommLayer : public SecureCommLayer
		{
		public:
			TlsCommLayer() = delete;
			TlsCommLayer(ConnectionBase& cnt, std::shared_ptr<const MbedTlsObj::TlsConfig> tlsConfig, bool reqPeerCert, std::shared_ptr<const MbedTlsObj::Session> session);

			TlsCommLayer(const TlsCommLayer& other) = delete;
			TlsCommLayer(TlsCommLayer&& other);

			virtual ~TlsCommLayer();

			TlsCommLayer& operator=(const TlsCommLayer& other) = delete;
			TlsCommLayer& operator=(TlsCommLayer&& other);

			using SecureCommLayer::SendRaw;
			virtual size_t SendRaw(const void* buf, const size_t size) override;

			using SecureCommLayer::RecvRaw;
			virtual size_t RecvRaw(void* buf, const size_t size) override;

			virtual void SetConnectionPtr(ConnectionBase& cnt) override;

			std::shared_ptr<MbedTlsObj::Session> GetSessionCopy() const;

			std::string GetPeerCertPem() const;
			std::string GetPublicKeyPem() const;

			virtual bool IsValid() const;

		private:
			std::unique_ptr<mbedtls_ssl_context> m_sslCtx;
			std::shared_ptr<const MbedTlsObj::TlsConfig> m_tlsConfig;
		};
	}
}
