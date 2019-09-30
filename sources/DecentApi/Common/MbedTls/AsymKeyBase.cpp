#include "AsymKeyBase.h"

#include <mbedtls/pk.h>

#include "MbedTlsException.h"
#include "Internal/Hasher.h"

using namespace Decent::MbedTlsObj;

void AsymKeyBase::FreeObject(mbedtls_pk_context * ptr)
{
	mbedtls_pk_free(ptr);
	delete ptr;
}

AsymKeyBase::AsymKeyBase() :
	ObjBase(new mbedtls_pk_context, &FreeObject)
{
	mbedtls_pk_init(Get());
}

AsymKeyBase::AsymKeyBase(AsymKeyBase && rhs) :
	ObjBase(std::forward<ObjBase>(rhs))
{
}

AsymKeyBase::~AsymKeyBase()
{
}

AsymKeyBase & AsymKeyBase::operator=(AsymKeyBase && rhs)
{
	ObjBase::operator=(std::forward<ObjBase>(rhs));
	return  *this;
}

bool AsymKeyBase::IsNull() const
{
	return ObjBase::IsNull() ||
		(mbedtls_pk_get_type(Get()) == mbedtls_pk_type_t::MBEDTLS_PK_NONE);
}

AsymKeyBase::AsymKeyBase(mbedtls_pk_context * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc)
{
}

void AsymKeyBase::VrfyDerSignNoBufferCheck(HashType hashType, const void * hashBuf, size_t hashSize, const void * signBuf, size_t signSize) const
{
	NullCheck();

	const uint8_t* hashBufByte = static_cast<const uint8_t*>(hashBuf);
	const uint8_t* signBufByte = static_cast<const uint8_t*>(signBuf);
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_verify, GetMutable(), detail::GetMsgDigestType(hashType),
		hashBufByte, hashSize, signBufByte, signSize);
}

std::vector<uint8_t> AsymKeyBase::GetPublicDer(size_t maxBufSize) const
{
	NullCheck();

	std::vector<uint8_t> res(maxBufSize);

	int len = mbedtls_pk_write_pubkey_der(GetMutable(), res.data(), res.size());
	if (len <= 0)
	{
		throw Decent::MbedTlsObj::MbedTlsException("mbedtls_pk_write_pubkey_der", len);
	}

	res.resize(len);
	res.shrink_to_fit();

	return res;
}

std::string AsymKeyBase::GetPublicPem(size_t maxBufSize) const
{
	NullCheck();

	std::string res(maxBufSize, '\0');

	CALL_MBEDTLS_C_FUNC(mbedtls_pk_write_pubkey_pem,
		GetMutable(), reinterpret_cast<unsigned char*>(&res[0]), maxBufSize);

	res.resize(std::strlen(res.c_str()));
	res.shrink_to_fit();

	return res;
}
