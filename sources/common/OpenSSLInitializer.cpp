#include "OpenSSLInitializer.h"

#include <openssl/ssl.h>

const OpenSSLInitializer & OpenSSLInitializer::Initialize()
{
	static const OpenSSLInitializer inst;
	return inst;
}

OpenSSLInitializer::OpenSSLInitializer()
{
	SSL_library_init();
}

OpenSSLInitializer::~OpenSSLInitializer()
{
}
