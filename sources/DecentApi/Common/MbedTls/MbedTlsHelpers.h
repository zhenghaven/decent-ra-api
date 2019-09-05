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

	}
}
