#include "MbedTlsInitializer.h"

#include <mbedtls/threading.h>

#include "../common/MbedTlsSubFunc.h"
#include "../common/CommonTool.h"

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
	COMMON_PRINTF("Initializing Mbed TLS ...\n");

	mbedtls_threading_set_alt(
		&DecentMbedTls::mbedtls_mutex_init,
		&DecentMbedTls::mbedtls_mutex_free,
		&DecentMbedTls::mbedtls_mutex_lock,
		&DecentMbedTls::mbedtls_mutex_unlock
	);
}
