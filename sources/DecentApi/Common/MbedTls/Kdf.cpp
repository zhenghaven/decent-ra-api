#include "Kdf.h"

#include <mbedtls/hkdf.h>

#include "Hasher.h"
#include "MbedTlsException.h"

using namespace Decent;
using namespace Decent::MbedTlsObj;

#define CHECK_MBEDTLS_RET(FUNCTION, ...) { int retVal = FUNCTION(__VA_ARGS__); if(retVal != MBEDTLS_SUCCESS_RET) { throw MbedTlsException(#FUNCTION, retVal); } }

void detail::HKDF(HashType hashType, const void * inKey, size_t inKeyLen, const void * label, size_t labelLen, const void * inSalt, size_t inSaltLen, void * outKey, size_t outKeyLen)
{
	CHECK_MBEDTLS_RET(mbedtls_hkdf, &GetMdInfo(hashType), static_cast<const unsigned char *>(inSalt), inSaltLen,
		static_cast<const unsigned char *>(inKey), inKeyLen,
		static_cast<const unsigned char *>(label), labelLen,
		static_cast<unsigned char *>(outKey), outKeyLen);
}
