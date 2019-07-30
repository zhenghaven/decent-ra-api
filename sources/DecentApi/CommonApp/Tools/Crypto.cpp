#include "../../Common/Tools/Crypto.h"

#include "../../Common/MbedTls/Gcm.h"

using namespace Decent;
using namespace Decent::MbedTlsObj;

//In default, we don't use platform specific function call for application side

void Tools::detail::PlatformAesGcmEncrypt(const void * keyPtr, const size_t keySize,
	const void * srcPtr, const size_t srcSize,
	void * destPtr,
	const void * ivPtr, const size_t ivSize,
	const void * addPtr, const size_t addSize,
	void * tagPtr, const size_t tagSize)
{
	GcmBase(keyPtr, keySize, GcmBase::Cipher::AES).Encrypt(srcPtr, srcSize,
		destPtr, srcSize,
		ivPtr, ivSize,
		addPtr, addSize,
		tagPtr, tagSize);
}

void Tools::detail::PlatformAesGcmDecrypt(const void * keyPtr, const size_t keySize,
	const void * srcPtr, const size_t srcSize,
	void * destPtr,
	const void * ivPtr, const size_t ivSize,
	const void * addPtr, const size_t addSize,
	const void * tagPtr, const size_t tagSize)
{
	GcmBase(keyPtr, keySize, GcmBase::Cipher::AES).Decrypt(srcPtr, srcSize, destPtr, srcSize,
		ivPtr, ivSize,
		addPtr, addSize,
		tagPtr, tagSize);
}
