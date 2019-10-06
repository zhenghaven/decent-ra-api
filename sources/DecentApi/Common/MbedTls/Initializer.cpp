#include "Initializer.h"

#include <mbedtls/threading.h>

#include "MbedTlsSubFunc.h"

using namespace Decent::MbedTlsObj;

namespace
{
	// Try to initialize the mbedTLS at the very beginning.
	static Initializer& init = Initializer::Init();
}

Initializer & Initializer::Init()
{
	static Initializer instance;
	return instance;
}

Initializer::~Initializer()
{
}

Initializer::Initializer()
{
	mbedtls_threading_set_alt(
		&MbedTls::mbedtls_mutex_init,
		&MbedTls::mbedtls_mutex_free,
		&MbedTls::mbedtls_mutex_lock,
		&MbedTls::mbedtls_mutex_unlock
	);
}
