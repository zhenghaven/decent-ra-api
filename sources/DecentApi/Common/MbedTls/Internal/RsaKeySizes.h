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

			constexpr char const PEM_BEGIN_PUBLIC_KEY_RSA[] = "-----BEGIN PUBLIC KEY-----\n";
			constexpr char const PEM_END_PUBLIC_KEY_RSA[] = "-----END PUBLIC KEY-----\n";

			constexpr size_t PEM_RSA_PUBLIC_HEADER_SIZE = sizeof(PEM_BEGIN_PUBLIC_KEY_RSA) - 1;
			constexpr size_t PEM_RSA_PUBLIC_FOOTER_SIZE = sizeof(PEM_END_PUBLIC_KEY_RSA) - 1;

			constexpr char const PEM_BEGIN_PRIVATE_KEY_RSA[] = "-----BEGIN RSA PRIVATE KEY-----\n";
			constexpr char const PEM_END_PRIVATE_KEY_RSA[] = "-----END RSA PRIVATE KEY-----\n";

			constexpr size_t PEM_RSA_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_RSA) - 1;
			constexpr size_t PEM_RSA_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_RSA) - 1;

			//################################
			//   Helper Functions
			//################################

			inline constexpr size_t CalcRsaPubDerSize(size_t sizeInByte)
			{
				return (38 + 2 * sizeInByte);
			}

			inline constexpr size_t CalcRsaPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
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