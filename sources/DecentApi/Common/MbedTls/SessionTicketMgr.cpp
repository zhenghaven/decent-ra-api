#include "SessionTicketMgr.h"

#include <mbedtls/ssl_ticket.h>

#include "../make_unique.h"
//#include "../Common.h"

#include "MbedTlsException.h"
#include "Drbg.h"

using namespace Decent::MbedTlsObj;

int SessionTicketMgrBase::Parse(void * p_ticket, mbedtls_ssl_session * session, unsigned char * buf, size_t len) noexcept
{
	if (!p_ticket)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	try
	{
		static_cast<SessionTicketMgrBase*>(p_ticket)->Parse(*session, static_cast<uint8_t *>(buf), len);

		return MBEDTLS_SUCCESS_RET;
	}
	catch (const MbedTlsException& e)
	{
		return e.GetErrorCode();
	}
	catch (...)
	{
		return -1;
	}
}

int SessionTicketMgrBase::Write(void * p_ticket, const mbedtls_ssl_session * session, unsigned char * start, const unsigned char * end, size_t * tlen, uint32_t * lifetime) noexcept
{
	if (!p_ticket)
	{
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
	}

	try
	{
		static_cast<SessionTicketMgrBase*>(p_ticket)->Write(*session,
			static_cast<uint8_t *>(start), static_cast<const uint8_t *>(end), *tlen, *lifetime);

		return MBEDTLS_SUCCESS_RET;
	}
	catch (const MbedTlsException& e)
	{
		return e.GetErrorCode();
	}
	catch (...)
	{
		return -1;
	}
}

void SessionTicketMgr::FreeObject(mbedtls_ssl_ticket_context * ptr)
{
	mbedtls_ssl_ticket_free(ptr);
	delete ptr;
}

SessionTicketMgr::SessionTicketMgr() :
	ObjBase(new mbedtls_ssl_ticket_context, &FreeObject),
	m_rng(Tools::make_unique<Drbg>())
{
	mbedtls_ssl_ticket_init(Get());

	CALL_MBEDTLS_C_FUNC(mbedtls_ssl_ticket_setup, Get(), &Drbg::CallBack, m_rng.get(), MBEDTLS_CIPHER_AES_256_GCM, MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME);
}

SessionTicketMgr::~SessionTicketMgr()
{
}

void SessionTicketMgr::Parse(mbedtls_ssl_session & session, uint8_t * buf, size_t len)
{
	NullCheck();

	//LOGI("Parse TLS Session Ticket");
	CALL_MBEDTLS_C_FUNC(mbedtls_ssl_ticket_parse, Get(), &session, buf, len);
}

void SessionTicketMgr::Write(const mbedtls_ssl_session & session, uint8_t * start, const uint8_t * end, size_t & tlen, uint32_t & lifetime)
{
	NullCheck();

	//LOGI("Write TLS Session Ticket");
	CALL_MBEDTLS_C_FUNC(mbedtls_ssl_ticket_write, Get(), &session, start, end, &tlen, &lifetime);
}

bool SessionTicketMgr::IsNull() const noexcept
{
	return ObjBase::IsNull() || (m_rng.get() == nullptr);
}
