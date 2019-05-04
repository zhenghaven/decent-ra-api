#include "Session.h"

#include <mbedtls/ssl.h>

using namespace Decent::MbedTlsObj;

void Session::FreeObject(mbedtls_ssl_session * ptr)
{
	mbedtls_ssl_session_free(ptr);
}

Session::Session() :
	ObjBase(new mbedtls_ssl_session, &FreeObject)
{
	mbedtls_ssl_session_init(Get());
}

Session::~Session()
{
}
