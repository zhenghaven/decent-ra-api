#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "../../Common/MbedTls/Drbg.h"
#include "../../Common/MbedTls/Entropy.h"
#include "../../Common/MbedTls/MbedTlsException.h"

#ifndef MBEDTLS_THREADING_C
#error "Implementation does not support non-multi-threading."
#endif // MBEDTLS_THREADING_C

using namespace Decent::MbedTlsObj;

namespace
{
	static inline mbedtls_ctr_drbg_context* CastCtx(void* state)
	{
		return static_cast<mbedtls_ctr_drbg_context*>(state);
	}
}

Drbg::Drbg() :
	m_state(new mbedtls_ctr_drbg_context)
{
	Entropy& entropy = Entropy::InitSharedEntropy();

	mbedtls_ctr_drbg_init(CastCtx(m_state));
	CALL_MBEDTLS_C_FUNC(mbedtls_ctr_drbg_seed, CastCtx(m_state), &mbedtls_entropy_func, entropy.Get(), nullptr, 0);
}

Drbg::~Drbg()
{
	mbedtls_ctr_drbg_context* ctxPtr = CastCtx(m_state);
	mbedtls_ctr_drbg_free(ctxPtr);
	delete ctxPtr;
	m_state = nullptr;
}

void Drbg::Rand(void* buf, const size_t size)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_ctr_drbg_random, m_state, static_cast<unsigned char *>(buf), size);
}
