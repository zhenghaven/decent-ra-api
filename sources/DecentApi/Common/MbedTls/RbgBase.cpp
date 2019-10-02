#include "RbgBase.h"

#include <mbedtls/cipher.h>

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
		RbgBase* rbgPtr = static_cast<RbgBase*>(ctx);
		rbgPtr->Rand(buf, len);
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
