#pragma once

#include "MbedTlsCppDefs.h"

struct mbedtls_md_info_t;

namespace Decent
{
	namespace MbedTlsObj
	{
		const mbedtls_md_info_t& GetMdInfo(HashType type);
	}
}
