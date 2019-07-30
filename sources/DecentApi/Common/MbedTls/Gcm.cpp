#include "Gcm.h"

#include <mbedtls/gcm.h>

#include "../make_unique.h"
#include "MbedTlsException.h"

using namespace Decent::MbedTlsObj;

namespace
{
	static constexpr uint8_t GENERAL_BITS_PER_BYTE = 8;
}

#define CHECK_MBEDTLS_RET(VAL, FUNCSTR) {int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { throw MbedTlsException(#FUNCSTR, retVal); } }

#define CHECK_MBEDTLS_RET_ERR_HDL(VAL, FUNCSTR, ERR_HDL) {int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { ERR_HDL; throw MbedTlsException(#FUNCSTR, retVal); } }

void GcmBase::FreeObject(mbedtls_gcm_context * ptr)
{
	mbedtls_gcm_free(ptr);
	delete ptr;
}

Decent::MbedTlsObj::GcmBase::GcmBase(const void * key, const size_t size, const GcmBase::Cipher cipher) :
	GcmBase(ConstructGcmWithKey(key, size, cipher).release(), &GcmBase::FreeObject)
{
}

void GcmBase::Encrypt(const void * inData, const size_t inLen, void * outData, const size_t outLen,
	const void* iv, const size_t ivLen, const void * add, const size_t addLen,
	void* tag, const size_t tagLen)
{
	if (!*this ||
		!inData || !outData || !iv || !tag ||
		inLen > outLen)
	{
		throw RuntimeException("Invalid input parameters for function " "GcmBase::Encrypt" ". ");
	}
	CHECK_MBEDTLS_RET(
		mbedtls_gcm_crypt_and_tag(
			Get(), MBEDTLS_GCM_ENCRYPT, inLen,
			static_cast<const uint8_t*>(iv), ivLen,
			static_cast<const uint8_t*>(add), addLen,
			static_cast<const uint8_t*>(inData),
			static_cast<uint8_t*>(outData),
			tagLen, static_cast<uint8_t*>(tag)
		),
		GcmBase::Encrypt
	);
}

void GcmBase::Decrypt(const void * inData, const size_t inLen, void * outData, const size_t outLen,
	const void * iv, const size_t ivLen, const void * add, const size_t addLen,
	const void* tag, const size_t tagLen)
{
	if (!*this ||
		!inData || !outData || !iv || !tag ||
		inLen > outLen)
	{
		throw RuntimeException("Invalid input parameters for function " "GcmBase::Decrypt" ". ");
	}
	CHECK_MBEDTLS_RET(
		mbedtls_gcm_auth_decrypt(Get(), inLen,
		static_cast<const uint8_t*>(iv), ivLen,
		static_cast<const uint8_t*>(add), addLen,
		static_cast<const uint8_t*>(tag), tagLen,
		static_cast<const uint8_t*>(inData),
		static_cast<uint8_t*>(outData)),
		GcmBase::Decrypt
	);
}

std::unique_ptr<mbedtls_gcm_context> GcmBase::ConstructGcmWithKey(const void * key, const size_t size, const GcmBase::Cipher cipher)
{
	if (!key)
	{
		throw RuntimeException("Invalid input parameters for function " "GcmBase::SetGcmKey" ". ");
	}

	mbedtls_cipher_id_t mbedTlsCipher;
	switch (cipher)
	{
	case Cipher::AES:
		mbedTlsCipher = mbedtls_cipher_id_t::MBEDTLS_CIPHER_ID_AES;
		break;
	default:
		throw RuntimeException("Invalid cipher for function " "GcmBase::SetGcmKey" ". ");
	}

	const uint8_t* keyByte = static_cast<const uint8_t*>(key);
	const unsigned int keySizeBits = static_cast<unsigned int>(size * GENERAL_BITS_PER_BYTE);

	if (size > keySizeBits)
	{
		throw RuntimeException("Key size overflow in function " "GcmBase::SetGcmKey" ". ");
	}

	std::unique_ptr<mbedtls_gcm_context> gcmCtx = Tools::make_unique<mbedtls_gcm_context>();
	mbedtls_gcm_init(gcmCtx.get());

	CHECK_MBEDTLS_RET_ERR_HDL(mbedtls_gcm_setkey(gcmCtx.get(), mbedTlsCipher, keyByte, keySizeBits), GcmBase::SetGcmKey,
		mbedtls_gcm_free(gcmCtx.get()));

	return gcmCtx;
}
