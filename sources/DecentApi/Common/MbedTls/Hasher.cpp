#include "Hasher.h"

#include <mbedtls/md.h>

#include "RuntimeException.h"

using namespace Decent;
using namespace Decent::MbedTlsObj;

const mbedtls_md_info_t& MbedTlsObj::GetMdInfo(HashType type)
{
	switch (type)
	{
	case HashType::SHA224:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA224);
	case HashType::SHA256:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256);
	case HashType::SHA384:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA384);
	case HashType::SHA512:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA512);
	default:
		throw MbedTlsObj::RuntimeException("Invalid hash type is given!");
	}
}
