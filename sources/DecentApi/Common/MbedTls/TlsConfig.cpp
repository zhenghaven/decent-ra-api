#include "TlsConfig.h"

#include <mbedtls/ssl.h>

#include "RbgBase.h"
#include "X509Cert.h"
#include "AsymKeyBase.h"
#include "SessionTicketMgr.h"
#include "MbedTlsException.h"

using namespace Decent::MbedTlsObj;

void TlsConfig::FreeObject(mbedtls_ssl_config * ptr)
{
	mbedtls_ssl_config_free(ptr);
	delete ptr;
}

int TlsConfig::CertVerifyCallBack(void * inst, mbedtls_x509_crt * cert, int depth, uint32_t * flag) noexcept
{
	if (!inst || !cert || !flag)
	{
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}

	try //This callback function is given to C functions, thus, we need to catch all exceptions and return error code instead.
	{
		return static_cast<TlsConfig*>(inst)->VerifyCert(*cert, depth, *flag);
	}
	catch (...)
	{
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
	
}

TlsConfig::TlsConfig(TlsConfig&& other) :
	ObjBase(std::forward<ObjBase>(other)),
	m_rng(std::move(other.m_rng)),
	m_ca(std::move(other.m_ca)),
	m_prvKey(std::move(other.m_prvKey)),
	m_cert(std::move(other.m_cert)),
	m_ticketMgr(std::move(other.m_ticketMgr))
{
	if (!IsNull())
	{
		mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);
	}
}

TlsConfig::TlsConfig(bool isStream, Mode cntMode, int preset, std::unique_ptr<RbgBase> rbg,
	std::shared_ptr<const X509Cert> ca, std::shared_ptr<const X509Cert> cert, std::shared_ptr<const AsymKeyBase> prvKey,
	std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	TlsConfig(std::move(rbg), std::move(ca), std::move(cert), std::move(prvKey), std::move(ticketMgr))
{
	mbedtls_ssl_conf_rng(Get(), &RbgBase::CallBack, m_rng.get());
	mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);

	mbedtls_ssl_conf_session_tickets(Get(), MBEDTLS_SSL_SESSION_TICKETS_ENABLED);

	if (m_ticketMgr)
	{
		mbedtls_ssl_conf_session_tickets_cb(Get(), &SessionTicketMgrBase::Write, &SessionTicketMgrBase::Parse, m_ticketMgr.get());
	}

	int endpoint = 0;
	switch (cntMode)
	{
	case Mode::ServerVerifyPeer:
	case Mode::ServerNoVerifyPeer:
		endpoint = MBEDTLS_SSL_IS_SERVER;

		break;
	case Mode::ClientHasCert:
	case Mode::ClientNoCert:
		endpoint = MBEDTLS_SSL_IS_CLIENT;

		break;
	default:
		throw RuntimeException("The given TLS connection mode is invalid.");
	}

	CALL_MBEDTLS_C_FUNC(mbedtls_ssl_config_defaults, Get(), endpoint,
		isStream ? MBEDTLS_SSL_TRANSPORT_STREAM : MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		preset);

	switch (cntMode)
	{
	case Mode::ServerVerifyPeer: //Usually server always has certificate & key.
	case Mode::ServerNoVerifyPeer:
	case Mode::ClientHasCert:
		if (!m_prvKey || !m_cert)
		{
			throw RuntimeException("Key or certificate is required for this TLS config.");
		}
		CALL_MBEDTLS_C_FUNC(mbedtls_ssl_conf_own_cert, Get(),
			const_cast<mbedtls_x509_crt*>(m_cert->Get()),
			const_cast<mbedtls_pk_context*>(m_prvKey->Get()));

		break;
	case Mode::ClientNoCert:
	default:
		break;
	}

	switch (cntMode)
	{
	case Mode::ServerNoVerifyPeer:
		mbedtls_ssl_conf_authmode(Get(), MBEDTLS_SSL_VERIFY_NONE);

		break;
	case Mode::ServerVerifyPeer:
	case Mode::ClientHasCert: //Usually in Decent RA, client side always verify server side.
	case Mode::ClientNoCert:
		if (!m_ca)
		{
			throw RuntimeException("CA's certificate is required for this TLS config.");
		}
		mbedtls_ssl_conf_ca_chain(Get(), const_cast<mbedtls_x509_crt*>(m_ca->Get()), nullptr);
		mbedtls_ssl_conf_authmode(Get(), MBEDTLS_SSL_VERIFY_REQUIRED);

		break;
	default:
		break;
	}
}

TlsConfig::~TlsConfig()
{
}

TlsConfig& TlsConfig::operator=(TlsConfig&& rhs)
{
	ObjBase::operator=(std::forward<ObjBase>(rhs));
	if (this != &rhs)
	{
		m_rng = std::move(rhs.m_rng);
		m_ca = std::move(rhs.m_ca);
		m_cert = std::move(rhs.m_cert);
		m_prvKey = std::move(rhs.m_prvKey);
		m_ticketMgr = std::move(rhs.m_ticketMgr);

		if (!IsNull())
		{
			mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);
		}
	}
	return *this;
}

bool TlsConfig::IsNull() const noexcept
{
	return ObjBase::IsNull() ||
		(m_rng.get() == nullptr);
}

TlsConfig::TlsConfig(std::unique_ptr<RbgBase> rbg,
	std::shared_ptr<const X509Cert> ca, std::shared_ptr<const X509Cert> cert, std::shared_ptr<const AsymKeyBase> prvKey,
	std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	ObjBase(new mbedtls_ssl_config, &FreeObject),
	m_rng(std::move(rbg)),
	m_ca(std::move(ca)),
	m_cert(std::move(cert)),
	m_prvKey(std::move(prvKey)),
	m_ticketMgr(std::move(ticketMgr))
{
	mbedtls_ssl_config_init(Get());
}
