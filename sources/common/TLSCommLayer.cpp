#include "TLSCommLayer.h"

#include <memory>

#include <mbedtls/ssl.h>

#include "Connection.h"
#include "MbedTlsObjects.h"

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

namespace
{
	static int MbedTlsSslSend(void *ctx, const unsigned char *buf, size_t len)
	{
		if (!ctx)
		{
			return -1;
		}

		return StaticConnection::SendRaw(ctx, buf, len);
	}

	static int MbedTlsSslRecv(void *ctx, unsigned char *buf, size_t len)
	{
		if (!ctx)
		{
			return -1;
		}

		return StaticConnection::ReceiveRaw(ctx, buf, len);
	}
}

static mbedtls_ssl_context* ConstructTlsConnection(void * const connectionPtr, bool reqPeerCert,
	const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig,
	const std::shared_ptr<const MbedTlsObj::X509Cert>& caCert,
	const std::shared_ptr<const MbedTlsObj::PKey>& selfPrvKey,
	const std::shared_ptr<const MbedTlsObj::X509Cert>& selfCert)
{
	if (!connectionPtr ||
		!tlsConfig || !caCert || !selfPrvKey || !selfCert ||
		!*tlsConfig || !*caCert || !*selfPrvKey || !*selfCert)
	{
		return nullptr;
	}

	std::unique_ptr<mbedtls_ssl_context> tlsCtx(new mbedtls_ssl_context);
	mbedtls_ssl_init(tlsCtx.get());
	if (mbedtls_ssl_setup(tlsCtx.get(), tlsConfig->GetInternalPtr()) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_ssl_free(tlsCtx.get());
		return nullptr;
	}

	mbedtls_ssl_set_bio(tlsCtx.get(), connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);
	mbedtls_ssl_set_hs_authmode(tlsCtx.get(), reqPeerCert ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
	//mbedtls_ssl_get_verify_result

	if (mbedtls_ssl_handshake(tlsCtx.get()) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_ssl_free(tlsCtx.get());
		return nullptr;
	}

	return tlsCtx.release();
}

TLSCommLayer::TLSCommLayer(void * const connectionPtr, 
	const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig,
	const std::shared_ptr<const MbedTlsObj::X509Cert>& caCert,
	const std::shared_ptr<const MbedTlsObj::PKey>& selfPrvKey,
	const std::shared_ptr<const MbedTlsObj::X509Cert>& selfCert,
	bool reqPeerCert
	) :
	m_sslCtx(ConstructTlsConnection(connectionPtr, reqPeerCert,
		tlsConfig, caCert, selfPrvKey, selfCert)),
	m_tlsConfig(tlsConfig),
	m_caCert(caCert),
	m_selfPrvKey(selfPrvKey),
	m_selfCert(selfCert),
	m_hasHandshaked(m_sslCtx != nullptr)
{
}

TLSCommLayer::TLSCommLayer(TLSCommLayer && other) :
	m_sslCtx(other.m_sslCtx),
	m_tlsConfig(std::move(other.m_tlsConfig)),
	m_selfPrvKey(std::move(other.m_selfPrvKey)),
	m_selfCert(std::move(other.m_selfCert)),
	m_hasHandshaked(other.m_hasHandshaked)
{
	other.m_sslCtx = nullptr;
	other.m_hasHandshaked = false;
}

TLSCommLayer::~TLSCommLayer()
{
	Destory();
}

void TLSCommLayer::Destory()
{
	if (m_sslCtx)
	{
		mbedtls_ssl_close_notify(m_sslCtx);
		mbedtls_ssl_free(m_sslCtx);
	}
	m_sslCtx = nullptr;
	m_tlsConfig.reset();
}

TLSCommLayer & TLSCommLayer::operator=(TLSCommLayer && other)
{
	if (this != &other)
	{
		m_sslCtx = other.m_sslCtx;
		m_tlsConfig = std::move(other.m_tlsConfig);
		m_selfPrvKey = std::move(other.m_selfPrvKey);
		m_selfCert = std::move(other.m_selfCert);
		m_hasHandshaked = other.m_hasHandshaked;

		other.m_sslCtx = nullptr;
		other.m_hasHandshaked = false;
	}
	return *this;
}

TLSCommLayer::operator bool() const
{
	return m_sslCtx != nullptr && m_tlsConfig && *m_tlsConfig && m_selfPrvKey && *m_selfPrvKey &&
		m_selfCert && *m_selfCert && m_hasHandshaked;
}

bool TLSCommLayer::ReceiveMsg(void * const connectionPtr, std::string & outMsg)
{
	if (!*this)
	{
		return false;
	}

	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);
	
	return mbedtls_ssl_read(m_sslCtx, reinterpret_cast<uint8_t*>(&outMsg[0]), outMsg.size()) > 0;
}

bool TLSCommLayer::SendMsg(void * const connectionPtr, const std::string & inMsg)
{
	if (!*this)
	{
		return false;
	}

	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);

	/*TODO: fixed partial write. */
	return mbedtls_ssl_write(m_sslCtx, reinterpret_cast<const uint8_t*>(inMsg.data()), inMsg.size()) > 0;
}

//TLSCommLayer::TLSCommLayer() :
//	m_sslCtx(new mbedtls_ssl_context)
//{
//	mbedtls_ssl_init(m_sslCtx);
//}
