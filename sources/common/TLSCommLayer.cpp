#include "TLSCommLayer.h"

#include <memory>

#include <mbedtls/ssl.h>

#include "CommonTool.h"
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

	static bool MbedTlsSslWriteWrap(mbedtls_ssl_context *ssl, const void* const buf, const size_t len)
	{
		size_t sentSize = 0;
		int res = 0;
		while (sentSize < len)
		{
			res = mbedtls_ssl_write(ssl, reinterpret_cast<const uint8_t*>(buf), len - sentSize);
			if (res < 0)
			{
				return false;
			}
			sentSize += res;
		}
		return true;
	}

	static bool MbedTlsSslReadWrap(mbedtls_ssl_context *ssl, void* const buf, const size_t len)
	{
		size_t recvSize = 0;
		int res = 0;
		while (recvSize < len)
		{
			res = mbedtls_ssl_read(ssl, reinterpret_cast<uint8_t*>(buf), len - recvSize);
			if (res < 0)
			{
				return false;
			}
			recvSize += res;
		}
		return true;
	}
}

static mbedtls_ssl_context* ConstructTlsConnection(void * const connectionPtr, bool reqPeerCert,
	const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig)
{
	if (!connectionPtr ||
		!tlsConfig || !*tlsConfig)
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

	int ret = 0;
	if ((ret = mbedtls_ssl_handshake(tlsCtx.get())) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_ssl_free(tlsCtx.get());
		return nullptr;
	}

	return tlsCtx.release();
}

TLSCommLayer::TLSCommLayer(void * const connectionPtr, const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig, bool reqPeerCert
	) :
	m_sslCtx(ConstructTlsConnection(connectionPtr, reqPeerCert,
		tlsConfig)),
	m_tlsConfig(tlsConfig),
	m_hasHandshaked(m_sslCtx != nullptr)
{
}

TLSCommLayer::TLSCommLayer(TLSCommLayer && other) :
	m_sslCtx(other.m_sslCtx),
	m_tlsConfig(std::move(other.m_tlsConfig)),
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
		m_hasHandshaked = other.m_hasHandshaked;

		other.m_sslCtx = nullptr;
		other.m_hasHandshaked = false;
	}
	return *this;
}

TLSCommLayer::operator bool() const
{
	return m_sslCtx != nullptr && m_tlsConfig && *m_tlsConfig && m_hasHandshaked;
}

bool TLSCommLayer::ReceiveMsg(void * const connectionPtr, std::string & outMsg)
{
	if (!*this)
	{
		return false;
	}
	uint64_t msgSize = 0;
	if (!MbedTlsSslReadWrap(m_sslCtx, &msgSize, sizeof(uint64_t)))
	{
		return false;
	}
	outMsg.resize(msgSize);
	return MbedTlsSslReadWrap(m_sslCtx, &outMsg[0], outMsg.size());
}

bool TLSCommLayer::SendMsg(void * const connectionPtr, const std::string & inMsg)
{
	if (!*this)
	{
		return false;
	}

	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);

	uint64_t msgSize = static_cast<uint64_t>(inMsg.size());
	return MbedTlsSslWriteWrap(m_sslCtx, &msgSize, sizeof(uint64_t)) && MbedTlsSslWriteWrap(m_sslCtx, inMsg.data(), inMsg.size());
}
