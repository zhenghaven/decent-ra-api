#include "TlsCommLayer.h"

#include <memory>

#include <mbedtls/ssl.h>

#include "../Common.h"
#include "../make_unique.h"

#include "../MbedTls/MbedTlsObjects.h"
#include "../MbedTls/TlsConfig.h"
#include "../MbedTls/MbedTlsException.h"

#include "NetworkException.h"
#include "ConnectionBase.h"

using namespace Decent;
using namespace Decent::Net;
using namespace Decent::MbedTlsObj;

#define CHECK_MBEDTLS_RET(VAL, FUNCSTR) {int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { throw Decent::MbedTlsObj::MbedTlsException(#FUNCSTR, retVal); } }

namespace
{
	static int MbedTlsSslSend(void *ctx, const unsigned char *buf, size_t len)
	{
		return ConnectionBase::SendRawCallback(ctx, buf, len);
	}

	static int MbedTlsSslRecv(void *ctx, unsigned char *buf, size_t len)
	{
		return ConnectionBase::ReceiveRawCallback(ctx, buf, len);
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
}

TlsCommLayer::TlsCommLayer(ConnectionBase& cnt, std::shared_ptr<const TlsConfig> tlsConfig, bool reqPeerCert) :
	m_sslCtx(Tools::make_unique<mbedtls_ssl_context>()),
	m_tlsConfig(tlsConfig)
{
	if (!tlsConfig || !*tlsConfig)
	{
		throw Exception("The parameter given to the TLS Communication Layer is invalid.");
	}

	mbedtls_ssl_init(m_sslCtx.get());

	int mbedRet = mbedtls_ssl_setup(m_sslCtx.get(), tlsConfig->Get());
	if (mbedRet != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_ssl_free(m_sslCtx.get());
		throw Decent::MbedTlsObj::MbedTlsException("TlsCommLayer::TlsCommLayer::mbedtls_ssl_setup", mbedRet);
	}

	mbedtls_ssl_set_bio(m_sslCtx.get(), &cnt, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);
	mbedtls_ssl_set_hs_authmode(m_sslCtx.get(), reqPeerCert ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);

	mbedRet = mbedtls_ssl_handshake(m_sslCtx.get());
	if (mbedRet != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_ssl_free(m_sslCtx.get());
		throw Decent::MbedTlsObj::MbedTlsException("TlsCommLayer::TlsCommLayer::mbedtls_ssl_handshake", mbedRet);
	}
}

TlsCommLayer::TlsCommLayer(TlsCommLayer && other) :
	m_sslCtx(std::move(other.m_sslCtx)),
	m_tlsConfig(std::move(other.m_tlsConfig))
{
	other.m_sslCtx = nullptr;
}

TlsCommLayer::~TlsCommLayer()
{
	try
	{
		mbedtls_ssl_close_notify(m_sslCtx.get());
	} catch (const std::exception&) { }

	mbedtls_ssl_free(m_sslCtx.get());
}

TlsCommLayer & TlsCommLayer::operator=(TlsCommLayer && other)
{
	if (this != &other)
	{
		m_sslCtx.swap(other.m_sslCtx);
		m_tlsConfig.swap(other.m_tlsConfig);
	}
	return *this;
}

TlsCommLayer::operator bool() const
{
	return m_sslCtx != nullptr && m_tlsConfig && *m_tlsConfig;
}

void TlsCommLayer::SendRaw(const void * buf, const size_t size)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	MbedTlsSslWriteWrap(m_sslCtx.get(), buf, size);
}

void TlsCommLayer::ReceiveRaw(void * buf, const size_t size)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	MbedTlsSslReadWrap(m_sslCtx.get(), buf, size);
}

void TlsCommLayer::SendMsg(const std::string & inMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	uint64_t msgSize = static_cast<uint64_t>(inMsg.size());
	MbedTlsSslWriteWrap(m_sslCtx.get(), &msgSize, sizeof(uint64_t));
	MbedTlsSslWriteWrap(m_sslCtx.get(), inMsg.data(), inMsg.size());
}

void TlsCommLayer::ReceiveMsg(std::string & outMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	uint64_t msgSize = 0;
	MbedTlsSslReadWrap(m_sslCtx.get(), &msgSize, sizeof(uint64_t));

	outMsg.resize(msgSize);

	MbedTlsSslReadWrap(m_sslCtx.get(), msgSize == 0 ? nullptr : &outMsg[0], outMsg.size());
}

void TlsCommLayer::SendMsg(const std::vector<uint8_t>& inMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	uint64_t msgSize = static_cast<uint64_t>(inMsg.size());
	MbedTlsSslWriteWrap(m_sslCtx.get(), &msgSize, sizeof(uint64_t));
	MbedTlsSslWriteWrap(m_sslCtx.get(), inMsg.data(), inMsg.size());
}

void TlsCommLayer::ReceiveMsg(std::vector<uint8_t>& outMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	uint64_t msgSize = 0;
	MbedTlsSslReadWrap(m_sslCtx.get(), &msgSize, sizeof(uint64_t));

	outMsg.resize(msgSize);

	MbedTlsSslReadWrap(m_sslCtx.get(), outMsg.data(), outMsg.size());
}

void TlsCommLayer::SetConnectionPtr(ConnectionBase& cnt)
{
	mbedtls_ssl_set_bio(m_sslCtx.get(), &cnt, &MbedTlsSslSend, &MbedTlsSslRecv, nullptr);
}

std::string TlsCommLayer::GetPeerCertPem() const
{
	const mbedtls_x509_crt* crtPtr = mbedtls_ssl_get_peer_cert(m_sslCtx.get());
	
	if (!*this || !crtPtr)
	{
		throw ConnectionNotEstablished();
	}
	//We just need the non-const pointer, and then we will return the PEM string.
	return Decent::MbedTlsObj::X509Cert(*const_cast<mbedtls_x509_crt*>(crtPtr)).ToPemString();
}

std::string TlsCommLayer::GetPublicKeyPem() const
{
	const mbedtls_x509_crt* crtPtr = mbedtls_ssl_get_peer_cert(m_sslCtx.get());

	if (!*this || !crtPtr)
	{
		throw ConnectionNotEstablished();
	}
	//We just need the non-const pointer, and then we will return the PEM string.
	return Decent::MbedTlsObj::X509Cert(*const_cast<mbedtls_x509_crt*>(crtPtr)).GetPublicKey().ToPubPemString();
}
