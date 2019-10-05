#pragma once

#include "Base64Sizes.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			inline constexpr size_t CalcPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
			{
				return headerSize +                        // Header size
					Base64EncodedSize(derMaxSize) +        // Base64 encoded size
					1 +                                    // Required by mbedtls_base64_encode
					(Base64EncodedSize(derMaxSize) / 64) + //'\n' for each line
					footerSize +                           // Footer size
					1;                                     // null terminator
			}
		}
	}
}
