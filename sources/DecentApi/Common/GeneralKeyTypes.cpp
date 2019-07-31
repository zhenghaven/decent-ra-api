#include "GeneralKeyTypes.h"

#include <mbedtls/platform_util.h>

using namespace Decent;

void detail::MemZeroize(void * buf, size_t size)
{
	mbedtls_platform_zeroize(buf, size);
}
