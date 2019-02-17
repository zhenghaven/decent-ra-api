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
			TlsCommLayer(void* const connectionPtr, const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig, bool reqPeerCert);

			TlsCommLayer(const TlsCommLayer& other) = delete;
			TlsCommLayer(TlsCommLayer&& other);

			virtual ~TlsCommLayer();

			TlsCommLayer& operator=(const TlsCommLayer& other) = delete;
			TlsCommLayer& operator=(TlsCommLayer&& other);

			operator bool() const;

			virtual bool ReceiveMsg(void* const connectionPtr, std::string& outMsg) override;
			virtual bool SendMsg(void* const connectionPtr, const std::string& inMsg) override;

		private:
			mbedtls_ssl_context * m_sslCtx;
			std::shared_ptr<const MbedTlsObj::TlsConfig> m_tlsConfig;
			bool m_hasHandshaked;
		};
	}
}
