#pragma once

#include "EcKeySizes.h"
#include "RsaKeySizes.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			constexpr size_t ECP_MAX_BITS = 521;
			constexpr size_t MPI_MAX_SIZE = 1024; // in bignum.h

			constexpr size_t ECP_MAX_BYTES = (ECP_MAX_BITS + 7) / 8;

			// Public key sizes:
			// ECP:
			constexpr size_t ECP_PUB_DER_MAX_BYTES = CalcEcpPubDerSize(ECP_MAX_BYTES);

			constexpr size_t ECP_PUB_PEM_MAX_BYTES =
				CalcEcpPemMaxBytes(ECP_PUB_DER_MAX_BYTES, PEM_EC_PUBLIC_HEADER_SIZE, PEM_EC_PUBLIC_FOOTER_SIZE);

			// RSA:
			constexpr size_t RSA_PUB_DER_MAX_BYTES = CalcRsaPubDerSize(MPI_MAX_SIZE);

			constexpr size_t RSA_PUB_PEM_MAX_BYTES =
				CalcRsaPemMaxBytes(RSA_PUB_DER_MAX_BYTES, PEM_RSA_PUBLIC_HEADER_SIZE, PEM_RSA_PUBLIC_FOOTER_SIZE);

			// MAX:
			constexpr size_t PUB_DER_MAX_BYTES =
				ECP_PUB_DER_MAX_BYTES > RSA_PUB_DER_MAX_BYTES ? ECP_PUB_DER_MAX_BYTES : RSA_PUB_DER_MAX_BYTES;

			constexpr size_t PUB_PEM_MAX_BYTES =
				ECP_PUB_PEM_MAX_BYTES > RSA_PUB_PEM_MAX_BYTES ? ECP_PUB_PEM_MAX_BYTES : RSA_PUB_PEM_MAX_BYTES;

			// Private key sizes:
			// ECP:
			constexpr size_t ECP_PRV_DER_MAX_BYTES = CalcEcpPrvDerSize(ECP_MAX_BYTES);

			constexpr size_t ECP_PRV_PEM_MAX_BYTES =
				CalcEcpPemMaxBytes(ECP_PRV_DER_MAX_BYTES, PEM_EC_PRIVATE_HEADER_SIZE, PEM_EC_PRIVATE_FOOTER_SIZE);
		}
	}
}
