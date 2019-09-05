#include "SafeWrappers.h"

#include <mbedtls/platform_util.h>

using namespace Decent::MbedTlsObj;

void detail::MemZeroize(void * buf, size_t size)
{
	mbedtls_platform_zeroize(buf, size);
}
