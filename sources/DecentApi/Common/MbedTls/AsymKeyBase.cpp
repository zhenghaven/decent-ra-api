#include "AsymKeyBase.h"

#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/rsa.h>

#include "RbgBase.h"
#include "SafeWrappers.h"
#include "MbedTlsException.h"
#include "Internal/Hasher.h"
#include "Internal/AsymKeyBase.h"

using namespace Decent::MbedTlsObj;

void AsymKeyBase::FreeObject(mbedtls_pk_context * ptr)
{
	mbedtls_pk_free(ptr);
	delete ptr;
}

AsymAlgmType AsymKeyBase::GetAlgmTypeFromContext(const mbedtls_pk_context & ctx)
{
	mbedtls_pk_type_t type = mbedtls_pk_get_type(&ctx);

	switch (type)
	{
	case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY:
	case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH:
	case mbedtls_pk_type_t::MBEDTLS_PK_ECDSA:
		return AsymAlgmType::EC;
	case mbedtls_pk_type_t::MBEDTLS_PK_RSA:
	case mbedtls_pk_type_t::MBEDTLS_PK_RSA_ALT:
	case mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS:
		return AsymAlgmType::RSA;
	default:
		throw RuntimeException("The given asymmetric key algorithm type isn't supported.");
	}
}

AsymKeyType AsymKeyBase::GetKeyTypeFromContext(mbedtls_pk_context & ctx, RbgBase& rbg)
{
	AsymAlgmType algmType = GetAlgmTypeFromContext(ctx);

	switch (algmType)
	{
	case AsymAlgmType::EC:
		return GetKeyTypeFromContext(*mbedtls_pk_ec(ctx));
	case AsymAlgmType::RSA:
	default: //GetAlgmTypeFromContext won't give us invalid result.
		return GetKeyTypeFromContext(*mbedtls_pk_rsa(ctx));
	}
}

AsymKeyType AsymKeyBase::GetKeyTypeFromContext(mbedtls_ecp_keypair & ctx, RbgBase& rbg)
{
	if (CheckPublicKeyInContext(ctx))
	{
		// Check if public is valid.
		// Ideally public should be there even if it is private key context.
		
		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private : AsymKeyType::Public;
	}
	else
	{
		// Public key is not in context, probably a private key?
		
		CompletePublicKeyInContext(ctx, rbg); //Try to fill in the public key.

		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private :
			throw RuntimeException("Invalid EC key context. Both private key and public key are invalid.");
	}
}

AsymKeyType AsymKeyBase::GetKeyTypeFromContext(mbedtls_rsa_context & ctx)
{
	if (CheckPublicKeyInContext(ctx))
	{
		// Check if public is valid.
		// Ideally public should be there even if it is private key context.

		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private : AsymKeyType::Public;
	}
	else
	{
		// Public key is not in context, probably a private key?

		CompletePublicKeyInContext(ctx); //Try to fill in the public key.

		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private :
			throw RuntimeException("Invalid RSA key context. Both private key and public key are invalid.");
	}
}

AsymKeyType AsymKeyBase::GetKeyTypeFromContext(const mbedtls_pk_context & ctx)
{
	AsymAlgmType algmType = GetAlgmTypeFromContext(ctx);

	switch (algmType)
	{
	case AsymAlgmType::EC:
		return GetKeyTypeFromContext(*static_cast<const mbedtls_ecp_keypair*>(mbedtls_pk_ec(ctx)));
	case AsymAlgmType::RSA:
	default: //GetAlgmTypeFromContext won't give us invalid result.
		return GetKeyTypeFromContext(*static_cast<const mbedtls_rsa_context*>(mbedtls_pk_rsa(ctx)));
	}
}

AsymKeyType AsymKeyBase::GetKeyTypeFromContext(const mbedtls_ecp_keypair & ctx)
{
	if (CheckPublicKeyInContext(ctx))
	{
		// Check if public is valid.
		// Ideally public should be there even if it is private key context.

		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private : AsymKeyType::Public;
	}
	else
	{
		// Public key is not in context, probably a private key?
		// We don't try to complete the key here.
		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private :
			throw RuntimeException("Invalid EC key context. Both private key and public key are invalid.");
	}
}

AsymKeyType AsymKeyBase::GetKeyTypeFromContext(const mbedtls_rsa_context & ctx)
{
	if (CheckPublicKeyInContext(ctx))
	{
		// Check if public is valid.
		// Ideally public should be there even if it is private key context.

		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private : AsymKeyType::Public;
	}
	else
	{
		// Public key is not in context, probably a private key?
		// We don't try to complete the key here.
		return CheckPrivateKeyInContext(ctx) ? AsymKeyType::Private :
			throw RuntimeException("Invalid RSA key context. Both private key and public key are invalid.");
	}
}

bool AsymKeyBase::CheckPublicKeyInContext(const mbedtls_ecp_keypair & ctx)
{
	int res = mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q);
	return res == MBEDTLS_SUCCESS_RET ? true :
		(res == MBEDTLS_ERR_ECP_INVALID_KEY ? false :
			throw MbedTlsException("mbedtls_ecp_check_pubkey", res));
}

bool AsymKeyBase::CheckPrivateKeyInContext(const mbedtls_ecp_keypair & ctx)
{
	int res = mbedtls_ecp_check_privkey(&ctx.grp, &ctx.d);
	return res == MBEDTLS_SUCCESS_RET ? true :
		(res == MBEDTLS_ERR_ECP_INVALID_KEY ? false :
			throw MbedTlsException("mbedtls_ecp_check_privkey", res));
}

void AsymKeyBase::CompletePublicKeyInContext(mbedtls_ecp_keypair & ctx, RbgBase& rbg)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_mul, &ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, &RbgBase::CallBack, &rbg);
}

bool AsymKeyBase::CheckPublicKeyInContext(const mbedtls_rsa_context & ctx)
{
	int res = mbedtls_rsa_check_pubkey(&ctx);
	return res == MBEDTLS_SUCCESS_RET ? true :
		(res == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED ? false :
			throw MbedTlsException("mbedtls_rsa_check_pubkey", res));
}

bool AsymKeyBase::CheckPrivateKeyInContext(const mbedtls_rsa_context & ctx)
{
	int res = mbedtls_rsa_check_privkey(&ctx);
	return res == MBEDTLS_SUCCESS_RET ? true :
		(res == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED ? false :
			throw MbedTlsException("mbedtls_rsa_check_privkey", res));
}

void AsymKeyBase::CompletePublicKeyInContext(mbedtls_rsa_context & ctx)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_rsa_complete, &ctx);
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

AsymKeyBase::AsymKeyBase(mbedtls_pk_context & other) :
	ObjBase(&other, &DoNotFree)
{
}

AsymKeyBase::AsymKeyBase(const std::string & pem) :
	AsymKeyBase()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_parse_key, Get(),
		reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1, nullptr, 0);
}

AsymKeyBase::AsymKeyBase(const std::vector<uint8_t>& der) :
	AsymKeyBase()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_parse_key, Get(),
		der.data(), der.size(), nullptr, 0);
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

AsymAlgmType AsymKeyBase::GetAlgmType() const
{
	NullCheck();
	return GetAlgmTypeFromContext(*Get());
}

AsymKeyType AsymKeyBase::GetKeyType() const
{
	NullCheck();
	return GetKeyTypeFromContext(*Get());
}

std::vector<uint8_t> AsymKeyBase::GetPublicDer() const
{
	return GetPublicDer(detail::PUB_DER_MAX_BYTES);
}

std::string AsymKeyBase::GetPublicPem() const
{
	return GetPublicPem(detail::PUB_PEM_MAX_BYTES);
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

void AsymKeyBase::GetPrivateDer(std::vector<uint8_t>& out, size_t maxBufSize) const
{
	NullCheck();

	std::vector<uint8_t> res(maxBufSize);

	int len = mbedtls_pk_write_key_der(GetMutable(), res.data(), res.size());
	if (len <= 0)
	{
		throw Decent::MbedTlsObj::MbedTlsException("mbedtls_pk_write_pubkey_der", len);
	}

	out.resize(len);

	std::memcpy(out.data(), res.data(), len);

	ZeroizeContainer(res);
}

void AsymKeyBase::GetPrivatePem(std::string & out, size_t maxBufSize) const
{
	NullCheck();

	std::string res(maxBufSize + 1, '\0');

	CALL_MBEDTLS_C_FUNC(mbedtls_pk_write_pubkey_pem,
		GetMutable(), reinterpret_cast<unsigned char*>(&res[0]), maxBufSize);

	size_t len = std::strlen(res.c_str());
	out.resize(len);

	std::memcpy(&out[0], res.c_str(), len);

	ZeroizeContainer(res);
}
