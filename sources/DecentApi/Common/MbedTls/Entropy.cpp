#include "Entropy.h"

#include <mbedtls/entropy.h>

#include "Initializer.h"

using namespace Decent::MbedTlsObj;

void Entropy::FreeObject(mbedtls_entropy_context * ptr)
{
	mbedtls_entropy_free(ptr);
	delete ptr;
}

Entropy & Entropy::InitSharedEntropy()
{
	static Entropy entropy;
	return entropy;
}

Entropy::Entropy() :
	ObjBase(new mbedtls_entropy_context, &FreeObject),
	m_mbedTlsInit(Initializer::Init())
{
	mbedtls_entropy_init(Get());
}
