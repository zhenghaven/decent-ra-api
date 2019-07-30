#include "../../Common/MbedTls/MbedTlsHelpers.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "../../Common/MbedTls/Drbg.h"
#include "../../Common/MbedTls/MbedTlsObjects.h"
#include "../../Common/MbedTls/MbedTlsException.h"

#ifndef MBEDTLS_THREADING_C
#error "Implementation does not support non-multi-threading."
#endif // MBEDTLS_THREADING_C

using namespace Decent::MbedTlsObj;

#define CHECK_MBEDTLS_RET(VAL) { int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { throw MbedTlsException(__FUNCTION__, retVal); } }

namespace
{
	EntropyCtx& GetEntropy()
	{
		static EntropyCtx entropy;
		return entropy;
	}

	static inline mbedtls_ctr_drbg_context* CastCtx(void* state)
	{
		return static_cast<mbedtls_ctr_drbg_context*>(state);
	}

	static inline Drbg& CastDrbg(void* state)
	{
		return *static_cast<Drbg*>(state);
	}
}

Drbg::Drbg() :
	m_state(new mbedtls_ctr_drbg_context)
{
	EntropyCtx& entropy = GetEntropy();

	mbedtls_ctr_drbg_init(CastCtx(m_state));
	CHECK_MBEDTLS_RET(mbedtls_ctr_drbg_seed(CastCtx(m_state), &mbedtls_entropy_func, entropy.Get(), nullptr, 0));
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
	CHECK_MBEDTLS_RET(mbedtls_ctr_drbg_random(m_state, static_cast<unsigned char *>(buf), size));
}

int Drbg::CallBack(void * ctx, unsigned char * buf, size_t len)
{
	if (!ctx)
	{
		return -1;
	}

	try
	{
		CastDrbg(ctx).Rand(buf, len);
		return 0;
	}
	catch (const std::exception&)
	{
		return -1;
	}
}
