#include "SessionTicketMgr.h"

#include <mbedtls/ssl_ticket.h>

#include "../make_unique.h"
//#include "../Common.h"

#include "MbedTlsException.h"
#include "Drbg.h"

using namespace Decent::MbedTlsObj;

void SessionTicketMgr::FreeObject(mbedtls_ssl_ticket_context * ptr)
{
	mbedtls_ssl_ticket_free(ptr);
}

SessionTicketMgr::SessionTicketMgr() :
	ObjBase(new mbedtls_ssl_ticket_context, &FreeObject),
	m_rng(Tools::make_unique<Drbg>())
{
	mbedtls_ssl_ticket_init(Get());

	int mbedtlsRet = mbedtls_ssl_ticket_setup(Get(), &Drbg::CallBack, m_rng.get(), MBEDTLS_CIPHER_AES_256_GCM, MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME);
	if (mbedtlsRet != MBEDTLS_SUCCESS_RET)
	{
		FreeObject(Get());
		throw MbedTlsException("mbedtls_ssl_ticket_setup", mbedtlsRet);
	}
}

SessionTicketMgr::~SessionTicketMgr()
{
}

int SessionTicketMgr::Parse(mbedtls_ssl_session & session, uint8_t * buf, size_t len)
{
	//LOGI("Parse TLS Session Ticket");
	return mbedtls_ssl_ticket_parse(Get(), &session, buf, len);
}

int Decent::MbedTlsObj::SessionTicketMgr::Write(const mbedtls_ssl_session & session, uint8_t * start, const uint8_t * end, size_t & tlen, uint32_t & lifetime)
{
	//LOGI("Write TLS Session Ticket");
	return mbedtls_ssl_ticket_write(Get(), &session, start, end, &tlen, &lifetime);
}
