#pragma once

#include <cstdint>

#include <string>
#include <vector>
#include <array>

#include "../GeneralKeyTypes.h"

typedef struct mbedtls_asn1_named_data mbedtls_asn1_named_data;
typedef struct mbedtls_asn1_buf mbedtls_asn1_buf;

namespace Decent
{
	namespace MbedTlsHelper
	{
		//Dest is allocated but not initialized.
		bool MbedTlsAsn1DeepCopy(mbedtls_asn1_buf& dest, const mbedtls_asn1_buf& src);

		//Dest is allocated but not initialized.
		bool MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data& dest, const mbedtls_asn1_named_data& src);

		//Dest can be null. If it's not null, it will be freed before copy.
		bool MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data*& dest, const mbedtls_asn1_named_data& src);

		bool CalcCmacAes128(const General128BitKey& key, const uint8_t* data, size_t dataSize, General128Tag& outTag);
		bool CalcCmacAes128(const General128BitKey& key, const uint8_t* data, size_t dataSize, uint8_t(&outTag)[GENERAL_128BIT_16BYTE_SIZE]);

		bool VerifyCmacAes128(const General128BitKey& key, const uint8_t* data, size_t dataSize, const General128Tag& inTag);
		bool VerifyCmacAes128(const General128BitKey& key, const uint8_t* data, size_t dataSize, const uint8_t(&inTag)[GENERAL_128BIT_16BYTE_SIZE]);

		bool CkdfAes128(const uint8_t* key, size_t keySize, const char* label, size_t labelLen, General128BitKey& outKey);

		template<size_t keySize>
		bool CkdfAes128(const std::array<uint8_t, keySize>& key, const std::string& label, General128BitKey& outKey)
		{
			return CkdfAes128(key.data(), key.size(), label.data(), label.size(), outKey);
		}

	}
}
