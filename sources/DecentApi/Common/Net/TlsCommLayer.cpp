#include "TlsCommLayer.h"

#include <memory>

#include <mbedtls/ssl.h>

#include "../Common.h"

#include "../MbedTls/MbedTlsObjects.h"

#include "NetworkException.h"
#include "Connection.h"

using namespace Decent::Net;
using namespace Decent;

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

namespace
{
	static int MbedTlsSslSend(void *ctx, const unsigned char *buf, size_t len)
	{
		return StatConnection::SendRawCallback(ctx, buf, len);
	}

	static int MbedTlsSslRecv(void *ctx, unsigned char *buf, size_t len)
	{
		return StatConnection::ReceiveRawCallback(ctx, buf, len);
	}

	static void MbedTlsSslWriteWrap(mbedtls_ssl_context *ssl, const void* const buf, const size_t len)
	{
		size_t sentSize = 0;
		int res = 0;
		while (sentSize < len)
		{
			res = mbedtls_ssl_write(ssl, reinterpret_cast<const uint8_t*>(buf), len - sentSize); //Pure C function, assume throw();
			if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				throw Exception("TLS send data failed.");
			}
			else if(res >= 0)
			{
				sentSize += res;
			}
		}
	}

	static void MbedTlsSslReadWrap(mbedtls_ssl_context *ssl, void* const buf, const size_t len)
	{
		size_t recvSize = 0;
		int res = 0;
		while (recvSize < len)
		{
			res = mbedtls_ssl_read(ssl, reinterpret_cast<uint8_t*>(buf), len - recvSize);
			if (res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ)
			{
				throw Exception("TLS read data failed.");
			}
			else if (res >= 0)
			{
				recvSize += res;
			}
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
		if (mbedtls_ssl_setup(tlsCtx.get(), tlsConfig->Get()) != MBEDTLS_SUCCESS_RET)
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
			LOGW("TLS Handshake Failed! code: %d_10/%#x_16.", ret, (-1 * ret));
			mbedtls_ssl_free(tlsCtx.get());
			return nullptr;
		}

		return tlsCtx.release();
	}
}

TlsCommLayer::TlsCommLayer(void * const connectionPtr, const std::shared_ptr<const MbedTlsObj::TlsConfig>& tlsConfig, bool reqPeerCert
	) :
	m_sslCtx(ConstructTlsConnection(connectionPtr, reqPeerCert,
		tlsConfig)),
	m_tlsConfig(tlsConfig),
	m_hasHandshaked(m_sslCtx != nullptr)
{
}

TlsCommLayer::TlsCommLayer(TlsCommLayer && other) :
	m_sslCtx(other.m_sslCtx),
	m_tlsConfig(std::move(other.m_tlsConfig)),
	m_hasHandshaked(other.m_hasHandshaked)
{
	other.m_sslCtx = nullptr;
	other.m_hasHandshaked = false;
}

TlsCommLayer::~TlsCommLayer()
{
	if (m_sslCtx)
	{
		try
		{
			mbedtls_ssl_close_notify(m_sslCtx);
		}
		catch (const std::exception&)
		{
		}
		mbedtls_ssl_free(m_sslCtx);
	}
	m_sslCtx = nullptr;
	m_tlsConfig.reset();
}

TlsCommLayer & TlsCommLayer::operator=(TlsCommLayer && other)
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

TlsCommLayer::operator bool() const
{
	return m_sslCtx != nullptr && m_tlsConfig && *m_tlsConfig && m_hasHandshaked;
}

void TlsCommLayer::SendRaw(void * const connectionPtr, const void * buf, const size_t size)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);
	MbedTlsSslWriteWrap(m_sslCtx, buf, size);
}

void TlsCommLayer::ReceiveRaw(void * const connectionPtr, void * buf, const size_t size)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}
	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);

	MbedTlsSslReadWrap(m_sslCtx, buf, size);
}

void TlsCommLayer::SendMsg(void * const connectionPtr, const std::string & inMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);

	uint64_t msgSize = static_cast<uint64_t>(inMsg.size());
	MbedTlsSslWriteWrap(m_sslCtx, &msgSize, sizeof(uint64_t));
	MbedTlsSslWriteWrap(m_sslCtx, inMsg.data(), inMsg.size());
}

void TlsCommLayer::ReceiveMsg(void * const connectionPtr, std::string & outMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	mbedtls_ssl_set_bio(m_sslCtx, connectionPtr, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);

	uint64_t msgSize = 0;
	MbedTlsSslReadWrap(m_sslCtx, &msgSize, sizeof(uint64_t));

	outMsg.resize(msgSize);

	MbedTlsSslReadWrap(m_sslCtx, &outMsg[0], outMsg.size());
}

std::string TlsCommLayer::GetPeerCertPem() const
{
	const mbedtls_x509_crt* crtPtr = mbedtls_ssl_get_peer_cert(m_sslCtx);

	if (*this && crtPtr)
	{
		return Decent::MbedTlsObj::X509Cert(*const_cast<mbedtls_x509_crt*>(crtPtr)).ToPemString(); 
		//We just need the non-const pointer, and then we will return the PEM string.
	}
	return std::string();
}

std::string TlsCommLayer::GetPublicKeyPem() const
{
	const mbedtls_x509_crt* crtPtr = mbedtls_ssl_get_peer_cert(m_sslCtx);

	if (*this && crtPtr)
	{
		return Decent::MbedTlsObj::X509Cert(*const_cast<mbedtls_x509_crt*>(crtPtr)).GetPublicKey().ToPubPemString();
		//We just need the non-const pointer, and then we will return the PEM string.
	}
	return std::string();
}
