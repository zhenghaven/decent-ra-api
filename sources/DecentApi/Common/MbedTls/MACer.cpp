#include "MACer.h"

#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>

#include "MbedTlsException.h"

using namespace Decent::MbedTlsObj;

#define CALL_MBEDTLS_C_FUNC(FUNC, ...) {int retVal = FUNC(__VA_ARGS__); if(retVal != MBEDTLS_SUCCESS_RET) { throw Decent::MbedTlsObj::MbedTlsException(#FUNC, retVal); } }

namespace
{
	mbedtls_cipher_type_t GetMbedTlsCipherType(CipherType type, uint16_t bitSize, CipherMode mode)
	{
		switch (type)
		{
		case Decent::MbedTlsObj::CipherType::AES:
			switch (mode)
			{
			case Decent::MbedTlsObj::CipherMode::ECB:
				switch (bitSize)
				{
				case 128:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_ECB;
				case 192:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_ECB;
				case 256:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_ECB;
				}
			case Decent::MbedTlsObj::CipherMode::CBC:
				switch (bitSize)
				{
				case 128:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_CBC;
				case 192:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_CBC;
				case 256:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_CBC;
				}
			case Decent::MbedTlsObj::CipherMode::CTR:
				switch (bitSize)
				{
				case 128:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_CTR;
				case 192:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_CTR;
				case 256:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_CTR;
				}
			case Decent::MbedTlsObj::CipherMode::GCM:
				switch (bitSize)
				{
				case 128:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_GCM;
				case 192:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_GCM;
				case 256:
					return mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_GCM;
				}
			}
		}

		throw RuntimeException("Cipher type given is not supported.");
	}
}

const mbedtls_cipher_info_t & Decent::MbedTlsObj::GetCipherInfo(CipherType type, uint16_t bitSize, CipherMode mode)
{
	const mbedtls_cipher_info_t* res = mbedtls_cipher_info_from_type(GetMbedTlsCipherType(type, bitSize, mode));
	if (res)
	{
		return *res;
	}
	else
	{
		throw RuntimeException("Mbed TLS cipher info not found.");
	}
}

void CipherBase::FreeObject(mbedtls_cipher_context_t * ptr)
{
	mbedtls_cipher_free(ptr);
	delete ptr;
}

CipherBase::CipherBase() :
	ObjBase(new mbedtls_cipher_context_t, &FreeObject)
{
	mbedtls_cipher_init(Get());
}

CipherBase::CipherBase(const mbedtls_cipher_info_t & cipherInfo) :
	CipherBase()
{
	// Destructor will be called automatically if exception is thrown. Cite: 
	//     https://stackoverflow.com/questions/17657761/is-the-destructor-called-when-a-delegating-constructor-throws
	CALL_MBEDTLS_C_FUNC(mbedtls_cipher_setup, Get(), &cipherInfo);
}

CipherBase::~CipherBase()
{
}

CMACerBase::CMACerBase(const mbedtls_cipher_info_t& cipherInfo, const void * key, const size_t keySize) :
	CipherBase(cipherInfo)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_cipher_cmac_starts, Get(), static_cast<const unsigned char*>(key), (keySize * BITS_PER_BYTE));
}

CMACerBase::~CMACerBase()
{
}

void CMACerBase::Update(const void * data, const size_t dataSize)
{
	if (dataSize > 0 && !data)
	{
		throw RuntimeException("Invalid parameter(s) given to CMACerBase::Update");
	}

	CALL_MBEDTLS_C_FUNC(mbedtls_cipher_cmac_update, Get(), static_cast<const unsigned char*>(data), dataSize);
}

void CMACerBase::Finish(void * output)
{
	if (!output)
	{
		throw RuntimeException("Invalid parameter(s) given to CMACerBase::Finish");
	}

	CALL_MBEDTLS_C_FUNC(mbedtls_cipher_cmac_finish, Get(), static_cast<unsigned char*>(output));
}
