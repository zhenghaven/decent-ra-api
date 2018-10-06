#include "../common/MbedTlsHelpers.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#ifndef MBEDTLS_THREADING_C
#error "Implementation does not support non-multi-threading."
#endif // MBEDTLS_THREADING_C

struct EntropyInstance
{
	mbedtls_entropy_context m_ctx;

	EntropyInstance()
	{
		mbedtls_entropy_init(&m_ctx);
	}

	~EntropyInstance()
	{
		mbedtls_entropy_free(&m_ctx);
	}
};

namespace
{
	static EntropyInstance gs_entropy;
}

void MbedTlsHelper::MbedTlsHelperDrbgInit(void *& ctx)
{
	mbedtls_ctr_drbg_context* ctxPtr = new mbedtls_ctr_drbg_context;

	mbedtls_ctr_drbg_init(ctxPtr);
	mbedtls_ctr_drbg_seed(ctxPtr, &mbedtls_entropy_func, &gs_entropy.m_ctx, nullptr, 0);

	ctx = ctxPtr;
}

int MbedTlsHelper::MbedTlsHelperDrbgRandom(void * ctx, unsigned char * output, size_t output_len)
{
	if (!ctx)
	{
		return -1;
	}
	
	return mbedtls_ctr_drbg_random(ctx, output, output_len);
}

void MbedTlsHelper::MbedTlsHelperDrbgFree(void *& ctx)
{
	if (!ctx)
	{
		return;
	}

	mbedtls_ctr_drbg_context* ctxPtr = reinterpret_cast<mbedtls_ctr_drbg_context*>(ctx);
	delete ctxPtr;

	ctx = nullptr;
}
