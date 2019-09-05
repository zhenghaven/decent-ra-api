#include "Kdf.h"

#include <mbedtls/hkdf.h>

#include "Hasher.h"
#include "MbedTlsException.h"

using namespace Decent;
using namespace Decent::MbedTlsObj;

#define CHECK_MBEDTLS_RET(FUNCTION, ...) { int retVal = FUNCTION(__VA_ARGS__); if(retVal != MBEDTLS_SUCCESS_RET) { throw MbedTlsException(#FUNCTION, retVal); } }

void detail::HKDF(HashType hashType, const void * inKey, const size_t inKeyLen, const void * label, const size_t labelLen, const void * inSalt, const size_t inSaltLen, void * outKey, const size_t outKeyLen)
{
	CHECK_MBEDTLS_RET(mbedtls_hkdf, &GetMdInfo(hashType), static_cast<const unsigned char *>(inSalt), inSaltLen,
		static_cast<const unsigned char *>(inKey), inKeyLen,
		static_cast<const unsigned char *>(label), labelLen,
		static_cast<unsigned char *>(outKey), outKeyLen);
}

std::vector<uint8_t> detail::GetCkdfByteSequence(const uint8_t ctr, const std::string & label, const uint16_t resKeyBitSize)
{
	constexpr size_t bufLenFixedPart = 4;

	std::vector<uint8_t> devBuf(label.size() + bufLenFixedPart, 0);

	devBuf[0] = ctr;

	memcpy(&devBuf[1], label.data(), label.size());

	uint16_t& keyLen = reinterpret_cast<uint16_t&>(devBuf[devBuf.size() - 2]);
	keyLen = resKeyBitSize;

	return devBuf;
}
