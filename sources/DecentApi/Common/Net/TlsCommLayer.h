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
	}

	namespace Net
	{
		class TlsCommLayer : public SecureCommLayer
		{
		public:
			TlsCommLayer() = delete;
			TlsCommLayer(ConnectionBase& cnt, std::shared_ptr<const MbedTlsObj::TlsConfig> tlsConfig, bool reqPeerCert);

			TlsCommLayer(const TlsCommLayer& other) = delete;
			TlsCommLayer(TlsCommLayer&& other);

			virtual ~TlsCommLayer();

			TlsCommLayer& operator=(const TlsCommLayer& other) = delete;
			TlsCommLayer& operator=(TlsCommLayer&& other);

			operator bool() const;

			virtual void SendRaw(const void* buf, const size_t size) override;
			virtual void SendRaw(ConnectionBase& cnt, const void* buf, const size_t size) override
			{
				SecureCommLayer::SendRaw(cnt, buf, size);
			}

			virtual void ReceiveRaw(void* buf, const size_t size) override;
			virtual void ReceiveRaw(ConnectionBase& cnt, void* buf, const size_t size) override
			{
				SecureCommLayer::ReceiveRaw(cnt, buf, size);
			}

			virtual void SendMsg(const std::string& inMsg) override;
			virtual void SendMsg(ConnectionBase& cnt, const std::string& inMsg) override
			{
				SecureCommLayer::SendMsg(cnt, inMsg);
			}

			virtual void ReceiveMsg(std::string& outMsg) override;
			virtual void ReceiveMsg(ConnectionBase& cnt, std::string& outMsg) override
			{
				SecureCommLayer::ReceiveMsg(cnt, outMsg);
			}

			virtual void SendMsg(const std::vector<uint8_t>& inMsg) override;
			virtual void SendMsg(ConnectionBase& cnt, const std::vector<uint8_t>& inMsg) override
			{
				SecureCommLayer::SendMsg(cnt, inMsg);
			}

			virtual void ReceiveMsg(std::vector<uint8_t>& outMsg) override;
			virtual void ReceiveMsg(ConnectionBase& cnt, std::vector<uint8_t>& outMsg) override
			{
				SecureCommLayer::ReceiveMsg(cnt, outMsg);
			}

			virtual void SetConnectionPtr(ConnectionBase& cnt) override;

			std::string GetPeerCertPem() const;
			std::string GetPublicKeyPem() const;

		private:
			std::unique_ptr<mbedtls_ssl_context> m_sslCtx;
			std::shared_ptr<const MbedTlsObj::TlsConfig> m_tlsConfig;
		};
	}
}
