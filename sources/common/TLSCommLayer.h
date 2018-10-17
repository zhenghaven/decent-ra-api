#pragma once

#include "SecureCommLayer.h"

#include <memory>

typedef struct mbedtls_ssl_context mbedtls_ssl_context;

namespace MbedTlsObj
{
	class TlsConfig;
	class PKey;
	class X509Cert;
}

class TLSCommLayer : public SecureCommLayer
{
public:
	TLSCommLayer() = delete;
	TLSCommLayer(void* const connectionPtr, 
		const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig,
		const std::shared_ptr<const MbedTlsObj::X509Cert>& caCert,
		const std::shared_ptr<const MbedTlsObj::PKey>& selfPrvKey,
		const std::shared_ptr<const MbedTlsObj::X509Cert>& selfCert,
		bool reqPeerCert);

	TLSCommLayer(const TLSCommLayer& other) = delete;
	TLSCommLayer(TLSCommLayer&& other);

	virtual ~TLSCommLayer();

	void Destory();

	TLSCommLayer& operator=(const TLSCommLayer& other) = delete;
	TLSCommLayer& operator=(TLSCommLayer&& other);

	operator bool() const;

	virtual bool ReceiveMsg(void* const connectionPtr, std::string& outMsg) override;
	virtual bool SendMsg(void* const connectionPtr, const std::string& inMsg) override;

private:
	mbedtls_ssl_context* m_sslCtx;
	std::shared_ptr<const MbedTlsObj::TlsConfig> m_tlsConfig;
	std::shared_ptr<const MbedTlsObj::X509Cert> m_caCert;
	std::shared_ptr<const MbedTlsObj::PKey> m_selfPrvKey;
	std::shared_ptr<const MbedTlsObj::X509Cert> m_selfCert;
	bool m_hasHandshaked;
};
