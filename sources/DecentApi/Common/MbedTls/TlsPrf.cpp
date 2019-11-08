#include "TlsPrf.h"

#include "Internal/Hasher.h"
#include "MbedTlsException.h"

using namespace Decent::MbedTlsObj;

extern "C" int mbedtlscpp_tls_prf_generic(mbedtls_md_type_t md_type,
	const unsigned char *secret, size_t slen,
	const char *label,
	const unsigned char *random, size_t rlen,
	unsigned char *dstbuf, size_t dlen);

void detail::TlsPrf(HashType hashType, const void * key, size_t keySize, const char * label, const void * random, size_t randomSize, void * dest, size_t destSize)
{
	CALL_MBEDTLS_C_FUNC(mbedtlscpp_tls_prf_generic, detail::GetMsgDigestType(hashType),
		static_cast<const uint8_t*>(key), keySize,
		label,
		static_cast<const uint8_t*>(random), randomSize,
		static_cast<uint8_t*>(dest), destSize);
}
