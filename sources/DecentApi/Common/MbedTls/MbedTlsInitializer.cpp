#include "MbedTlsInitializer.h"

#include <mbedtls/threading.h>

#include "../Common.h"
#include "MbedTlsSubFunc.h"

using namespace Decent::MbedTlsObj;

namespace
{
	//Init mbed TLS at the very begining.
	static MbedTlsInitializer& init = MbedTlsInitializer::GetInst();
}

MbedTlsInitializer & MbedTlsInitializer::GetInst()
{
	static MbedTlsInitializer instance;
	return instance;
}

MbedTlsInitializer::~MbedTlsInitializer()
{
}

MbedTlsInitializer::MbedTlsInitializer()
{
	LOGI("Initializing Mbed TLS ...\n");

	mbedtls_threading_set_alt(
		&MbedTls::mbedtls_mutex_init,
		&MbedTls::mbedtls_mutex_free,
		&MbedTls::mbedtls_mutex_lock,
		&MbedTls::mbedtls_mutex_unlock
	);
}
