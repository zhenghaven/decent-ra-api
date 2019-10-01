#pragma once

#include "Base64.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			constexpr char const PEM_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
			constexpr char const PEM_END_PUBLIC_KEY[] = "-----END PUBLIC KEY-----\n";

			constexpr size_t PEM_PUBLIC_HEADER_SIZE = sizeof(PEM_BEGIN_PUBLIC_KEY) - 1;
			constexpr size_t PEM_PUBLIC_FOOTER_SIZE = sizeof(PEM_END_PUBLIC_KEY) - 1;

			//constexpr char const PEM_BEGIN_PRIVATE_KEY_RSA[] = "-----BEGIN RSA PRIVATE KEY-----\n";
			//constexpr char const PEM_END_PRIVATE_KEY_RSA[] = "-----END RSA PRIVATE KEY-----\n";
			constexpr char const PEM_BEGIN_PRIVATE_KEY_EC[] = "-----BEGIN EC PRIVATE KEY-----\n";
			constexpr char const PEM_END_PRIVATE_KEY_EC[] = "-----END EC PRIVATE KEY-----\n";

			constexpr size_t PEM_EC_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_EC) - 1;
			constexpr size_t PEM_EC_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_EC) - 1;

			constexpr size_t ECP_MAX_BITS = 521;
			constexpr size_t MPI_MAX_SIZE = 1024; // in bignum.h

			constexpr size_t ECP_MAX_BYTES = (ECP_MAX_BITS + 7) / 8;

			inline constexpr size_t CalcEcpPubDerSize(size_t sizeInByte)
			{
				return (30 + 2 * sizeInByte);
			}

			inline constexpr size_t CalcEcpPrvDerSize(size_t sizeInByte)
			{
				return (29 + 3 * sizeInByte);
			}

			inline constexpr size_t CalcRsaPubDerSize(size_t sizeInByte)
			{
				return (38 + 2 * sizeInByte);
			}

			inline constexpr size_t CalcPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
			{
				return headerSize +
					Base64EncodedSize(derMaxSize) + 1 +
					(Base64EncodedSize(derMaxSize) / 64) +  //'\n' for each line.
					footerSize +
					1;                   //null terminator
			}

			// Public key sizes:
			// ECP:
			constexpr size_t ECP_PUB_DER_MAX_BYTES = CalcEcpPubDerSize(ECP_MAX_BYTES);

			constexpr size_t ECP_PUB_PEM_MAX_BYTES =
				CalcPemMaxBytes(ECP_PUB_DER_MAX_BYTES, PEM_PUBLIC_HEADER_SIZE, PEM_PUBLIC_FOOTER_SIZE);

			// RSA:
			constexpr size_t RSA_PUB_DER_MAX_BYTES = CalcRsaPubDerSize(MPI_MAX_SIZE);

			constexpr size_t RSA_PUB_PEM_MAX_BYTES =
				CalcPemMaxBytes(RSA_PUB_DER_MAX_BYTES, PEM_PUBLIC_HEADER_SIZE, PEM_PUBLIC_FOOTER_SIZE);

			// MAX:
			constexpr size_t PUB_DER_MAX_BYTES =
				ECP_PUB_DER_MAX_BYTES > RSA_PUB_DER_MAX_BYTES ? ECP_PUB_DER_MAX_BYTES : RSA_PUB_DER_MAX_BYTES;

			constexpr size_t PUB_PEM_MAX_BYTES =
				ECP_PUB_PEM_MAX_BYTES > RSA_PUB_PEM_MAX_BYTES ? ECP_PUB_PEM_MAX_BYTES : RSA_PUB_PEM_MAX_BYTES;

			// Private key sizes:
			// ECP:
			constexpr size_t ECP_PRV_DER_MAX_BYTES = CalcEcpPrvDerSize(ECP_MAX_BYTES);

			constexpr size_t ECP_PRV_PEM_MAX_BYTES =
				CalcPemMaxBytes(ECP_PRV_DER_MAX_BYTES, PEM_EC_PRIVATE_HEADER_SIZE, PEM_EC_PRIVATE_FOOTER_SIZE);
		}
	}
}
