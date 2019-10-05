#pragma once

#include <mbedtls/md.h>
#include "../MbedTlsCppDefs.h"
#include "../RuntimeException.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			inline constexpr mbedtls_md_type_t GetMsgDigestType(HashType type)
			{
				switch (type)
				{
				case HashType::SHA224:
					return mbedtls_md_type_t::MBEDTLS_MD_SHA224;
				case HashType::SHA256:
					return mbedtls_md_type_t::MBEDTLS_MD_SHA256;
				case HashType::SHA384:
					return mbedtls_md_type_t::MBEDTLS_MD_SHA384;
				case HashType::SHA512:
					return mbedtls_md_type_t::MBEDTLS_MD_SHA512;
				default:
					throw MbedTlsObj::RuntimeException("Invalid hash type is given!");
				}
			}

			inline constexpr HashType GetMsgDigestType(mbedtls_md_type_t type)
			{
				switch (type)
				{
				case mbedtls_md_type_t::MBEDTLS_MD_SHA224:
					return HashType::SHA224;
				case mbedtls_md_type_t::MBEDTLS_MD_SHA256:
					return HashType::SHA256;
				case mbedtls_md_type_t::MBEDTLS_MD_SHA384:
					return HashType::SHA384;
				case mbedtls_md_type_t::MBEDTLS_MD_SHA512:
					return HashType::SHA512;
				default:
					throw MbedTlsObj::RuntimeException("Invalid hash type is given!");
				}
			}
		}
	}
}
