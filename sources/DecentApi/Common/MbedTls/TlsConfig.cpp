#include "TlsConfig.h"

#include <mbedtls/ssl.h>

#include "../make_unique.h"
#include "Drbg.h"
#include "SessionTicketMgr.h"

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
	m_ticketMgr(std::move(other.m_ticketMgr))
{
	if (Get())
	{
		mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);

		mbedtls_ssl_conf_session_tickets(Get(), MBEDTLS_SSL_SESSION_TICKETS_ENABLED);

		if (m_ticketMgr)
		{
			mbedtls_ssl_conf_session_tickets_cb(Get(), &SessionTicketMgrBase::Write, &SessionTicketMgrBase::Parse, m_ticketMgr.get());
		}
	}
}

TlsConfig::TlsConfig(std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	ObjBase(new mbedtls_ssl_config, &FreeObject),
	m_rng(Tools::make_unique<Drbg>()),
	m_ticketMgr(ticketMgr)
{
	mbedtls_ssl_config_init(Get());
	mbedtls_ssl_conf_rng(Get(), &Drbg::CallBack, m_rng.get());
	mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);

	mbedtls_ssl_conf_session_tickets(Get(), MBEDTLS_SSL_SESSION_TICKETS_ENABLED);

	if (m_ticketMgr)
	{
		mbedtls_ssl_conf_session_tickets_cb(Get(), &SessionTicketMgrBase::Write, &SessionTicketMgrBase::Parse, m_ticketMgr.get());
	}
}

TlsConfig::~TlsConfig()
{
}

TlsConfig& TlsConfig::operator=(TlsConfig&& other) noexcept
{
	ObjBase::operator=(std::forward<ObjBase>(other));
	if (this != &other)
	{
		m_rng.swap(other.m_rng);
		m_ticketMgr.swap(other.m_ticketMgr);
	}
	return *this;
}

TlsConfig::operator bool() const noexcept
{
	return ObjBase::operator bool() && m_rng;
}
