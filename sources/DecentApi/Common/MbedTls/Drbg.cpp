#include "Drbg.h"

#include <mbedtls/cipher.h>

#include "MbedTlsCppDefs.h"
#include "MbedTlsException.h"

using namespace Decent::MbedTlsObj;

int RbgBase::CallBack(void * ctx, unsigned char * buf, size_t len) noexcept
{
	if (!ctx)
	{
		return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
	}

	try
	{
		static_cast<RbgBase*>(ctx)->Rand(buf, len);
		return MBEDTLS_SUCCESS_RET;
	}
	catch (const MbedTlsException& e)
	{
		return e.GetErrorCode();
	}
	catch (...)
	{
		return -1;
	}
}
