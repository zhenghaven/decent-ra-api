#include "../../Common/MbedTls/MbedTlsHelpers.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#ifndef MBEDTLS_THREADING_C
#error "Implementation does not support non-multi-threading."
#endif // MBEDTLS_THREADING_C

using namespace Decent::MbedTlsHelper;

namespace
{
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

	static EntropyInstance gs_entropy;

	static inline mbedtls_ctr_drbg_context* CastCtx(void* state)
	{
		return static_cast<mbedtls_ctr_drbg_context*>(state);
	}

	static inline Decent::MbedTlsHelper::Drbg& CastDrbg(void* state)
	{
		return *static_cast<Decent::MbedTlsHelper::Drbg*>(state);
	}
}

Drbg::Drbg() :
	m_state(new mbedtls_ctr_drbg_context)
{
	mbedtls_ctr_drbg_init(CastCtx(m_state));
	mbedtls_ctr_drbg_seed(CastCtx(m_state), &mbedtls_entropy_func, &gs_entropy.m_ctx, nullptr, 0);
}

Drbg::~Drbg()
{
	mbedtls_ctr_drbg_context* ctxPtr = CastCtx(m_state);
	delete ctxPtr;
	m_state = nullptr;
}

bool Drbg::Rand(void* buf, const size_t size)
{
	return mbedtls_ctr_drbg_random(m_state, static_cast<unsigned char *>(buf), size) == 0;
}

int Drbg::CallBack(void * ctx, unsigned char * buf, size_t len)
{
	return !ctx ? -1 :
		(CastDrbg(ctx).Rand(buf, len) ? 0 : -1);
}
