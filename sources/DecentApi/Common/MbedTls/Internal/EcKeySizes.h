#pragma once

#include "Base64Sizes.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			//################################
			//   Header and Footer
			//################################

			constexpr char const PEM_BEGIN_PUBLIC_KEY_EC[] = "-----BEGIN PUBLIC KEY-----\n";
			constexpr char const PEM_END_PUBLIC_KEY_EC[] = "-----END PUBLIC KEY-----\n";

			constexpr size_t PEM_EC_PUBLIC_HEADER_SIZE = sizeof(PEM_BEGIN_PUBLIC_KEY_EC) - 1;
			constexpr size_t PEM_EC_PUBLIC_FOOTER_SIZE = sizeof(PEM_END_PUBLIC_KEY_EC) - 1;

			constexpr char const PEM_BEGIN_PRIVATE_KEY_EC[] = "-----BEGIN EC PRIVATE KEY-----\n";
			constexpr char const PEM_END_PRIVATE_KEY_EC[] = "-----END EC PRIVATE KEY-----\n";

			constexpr size_t PEM_EC_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_EC) - 1;
			constexpr size_t PEM_EC_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_EC) - 1;

			//################################
			//   Helper Functions
			//################################

			inline constexpr size_t CalcEcpPubDerSize(size_t sizeInByte)
			{
				return (30 + 2 * sizeInByte);
			}

			inline constexpr size_t CalcEcpPrvDerSize(size_t sizeInByte)
			{
				return (29 + 3 * sizeInByte);
			}

			inline constexpr size_t CalcEcpPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
			{
				return headerSize +                        // Header size
					Base64EncodedSize(derMaxSize) +        // Base64 encoded size
					(Base64EncodedSize(derMaxSize) / 64) + //'\n' for each line
					footerSize +                           // Footer size
					1;                                     // null terminator
			}
		}
	}
}