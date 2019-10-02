#include "EcKey.h"

#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>

#include "RbgBase.h"
#include "BigNumber.h"
#include "MbedTlsException.h"

#include "Internal/Hasher.h"
#include "Internal/AsymKeyBase.h"

using namespace Decent::MbedTlsObj;

namespace
{
	static constexpr bool IsEcKeyType(mbedtls_pk_type_t type)
	{
		switch (type)
		{
		case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY:
		case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH:
		case mbedtls_pk_type_t::MBEDTLS_PK_ECDSA:
			return true;
		default:
			return false;
		}
	}

	static constexpr mbedtls_ecp_group_id GetEcGroupId(EcKeyType type)
	{
		switch (type)
		{
		case EcKeyType::SECP192R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192R1;
		case EcKeyType::SECP224R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224R1;
		case EcKeyType::SECP256R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1;
		case EcKeyType::SECP384R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP384R1;
		case EcKeyType::SECP521R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP521R1;
		case EcKeyType::BP256R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP256R1;
		case EcKeyType::BP384R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP384R1;
		case EcKeyType::BP512R1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP512R1;
		case EcKeyType::SECP192K1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192K1;
		case EcKeyType::SECP224K1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224K1;
		case EcKeyType::SECP256K1:
			return mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256K1;
		default:
			throw RuntimeException("The given EC key type is invalid.");
		}
	}

	static constexpr EcKeyType GetEcGroupId(mbedtls_ecp_group_id type)
	{
		switch (type)
		{
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192R1:
			return EcKeyType::SECP192R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224R1:
			return EcKeyType::SECP224R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1:
			return EcKeyType::SECP256R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP384R1:
			return EcKeyType::SECP384R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP521R1:
			return EcKeyType::SECP521R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP256R1:
			return EcKeyType::BP256R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP384R1:
			return EcKeyType::BP384R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP512R1:
			return EcKeyType::BP512R1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192K1:
			return EcKeyType::SECP192K1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224K1:
			return EcKeyType::SECP224K1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256K1:
			return EcKeyType::SECP256K1;
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE448:
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE25519:
		case mbedtls_ecp_group_id::MBEDTLS_ECP_DP_NONE:
		default:
			throw RuntimeException("The given EC key type is not supported.");
		}
	}
}

void EcGroup::FreeObject(mbedtls_ecp_group * ptr)
{
	mbedtls_ecp_group_free(ptr);
	delete ptr;
}

EcGroup::EcGroup() :
	ObjBase(new mbedtls_ecp_group, &FreeObject)
{
	mbedtls_ecp_group_init(Get());
}

EcGroup::EcGroup(const EcGroup & rhs) :
	EcGroup()
{
	rhs.NullCheck();
	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_group_copy, Get(), rhs.Get());
}

EcGroup::EcGroup(EcGroup && rhs) :
	ObjBase(std::forward<ObjBase>(rhs))
{
}

EcGroup::EcGroup(const mbedtls_ecp_group & rhs) :
	EcGroup()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_group_copy, Get(), &rhs);
}

EcGroup::~EcGroup()
{
}

void EcPublicKeyBase::CheckHasPublicKey(const mbedtls_ecp_keypair & ctx)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_check_pubkey, &ctx.grp, &ctx.Q);
}

EcPublicKeyBase::EcPublicKeyBase(EcPublicKeyBase && rhs) :
	AsymKeyBase(std::forward<AsymKeyBase>(rhs))
{
}

EcPublicKeyBase::EcPublicKeyBase(AsymKeyBase other) :
	AsymKeyBase(std::move(other))
{
	CheckIsAlgmTypeMatch(Get());
	EcPublicKeyBase::CheckHasPublicKey(*mbedtls_pk_ec(*Get()));
}

EcPublicKeyBase::EcPublicKeyBase(AsymKeyBase & other) :
	AsymKeyBase(CheckIsAlgmAndKeyTypeMatch(other))
{
}

EcPublicKeyBase::EcPublicKeyBase(mbedtls_pk_context & other) :
	AsymKeyBase(other)
{
	CheckIsAlgmTypeMatch(Get());
	EcPublicKeyBase::CheckHasPublicKey(*mbedtls_pk_ec(*Get()));
}

EcPublicKeyBase::EcPublicKeyBase(const std::string & pem) :
	AsymKeyBase(pem)
{
	CheckIsAlgmTypeMatch(Get());
}

EcPublicKeyBase::EcPublicKeyBase(const std::vector<uint8_t>& der) :
	AsymKeyBase(der)
{
	CheckIsAlgmTypeMatch(Get());
}

EcPublicKeyBase::EcPublicKeyBase(EcKeyType ecType, const BigNumberBase & x, const BigNumberBase & y) :
	EcPublicKeyBase(ecType)
{
	auto& ecCtx = GetEcContext();
	BigNumber ctxX = ecCtx.Q.X;
	BigNumber ctxY = ecCtx.Q.Y;
	BigNumber ctxZ = ecCtx.Q.Z;

	ctxX = x;
	ctxY = y;
	ctxZ = 1;

	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_check_pubkey, &(ecCtx.grp), &(ecCtx.Q));
}

EcPublicKeyBase::~EcPublicKeyBase()
{
}

void EcPublicKeyBase::CheckIsAlgmTypeMatch(mbedtls_pk_context * ctx)
{
	if (!ctx ||
		!IsEcKeyType(mbedtls_pk_get_type(ctx)))
	{
		throw RuntimeException("The PK context given to constructor doesn't match the type of the key.");
	}
}

AsymKeyBase EcPublicKeyBase::CheckIsAlgmAndKeyTypeMatch(AsymKeyBase& other)
{
	EcPublicKeyBase::CheckIsAlgmTypeMatch(other.Get());
	EcPublicKeyBase::CheckHasPublicKey(*mbedtls_pk_ec(*other.Get()));
	return std::move(other);
}

void EcPublicKeyBase::CheckIsEcTypeMatch(mbedtls_pk_context * ctx, EcKeyType ecType)
{
	if (!ctx ||
		!IsEcKeyType(mbedtls_pk_get_type(ctx)) ||
		GetEcGroupId(mbedtls_pk_ec(*ctx)->grp.id) != ecType)
	{
		throw RuntimeException("The Elliptic Curve type does not match the expected type.");
	}
}

AsymKeyBase& EcPublicKeyBase::CheckIsEcTypeMatch(AsymKeyBase & other, EcKeyType ecType)
{
	EcPublicKeyBase::CheckIsAlgmTypeMatch(other.Get());
	if (GetEcGroupId(mbedtls_pk_ec(*other.Get())->grp.id) != ecType)
	{
		throw RuntimeException("The Elliptic Curve type does not match the expected type.");
	}
	return other;
}

EcPublicKeyBase::EcPublicKeyBase() :
	AsymKeyBase()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_setup, Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY));
}

EcPublicKeyBase::EcPublicKeyBase(EcKeyType ecType) :
	EcPublicKeyBase()
{
	mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*Get());
	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_group_load, &(ecp->grp), GetEcGroupId(ecType));
}

EcPublicKeyBase & EcPublicKeyBase::operator=(EcPublicKeyBase && rhs)
{
	AsymKeyBase::operator=(std::forward<AsymKeyBase>(rhs));
	return *this;
}

bool EcPublicKeyBase::IsNull() const
{
	return AsymKeyBase::IsNull() ||
		!IsEcKeyType(mbedtls_pk_get_type(Get())) ||
		!mbedtls_pk_ec(*Get());
}

AsymAlgmType EcPublicKeyBase::GetAlgmType() const
{
	return AsymAlgmType::EC;
}

AsymKeyType EcPublicKeyBase::GetKeyType() const
{
	return AsymKeyType::Public;
}

EcKeyType EcPublicKeyBase::GetCurveType() const
{
	return GetEcGroupId(GetEcContext().grp.id);
}

mbedtls_ecp_keypair & EcPublicKeyBase::GetEcContext()
{
	NullCheck();
	return *mbedtls_pk_ec(*Get());
}

const mbedtls_ecp_keypair & EcPublicKeyBase::GetEcContext() const
{
	NullCheck();
	return *mbedtls_pk_ec(*Get());
}

std::vector<uint8_t> EcPublicKeyBase::GetPublicDer() const
{
	return AsymKeyBase::GetPublicDer(detail::ECP_PUB_DER_MAX_BYTES);
}

std::string EcPublicKeyBase::GetPublicPem() const
{
	return AsymKeyBase::GetPublicPem(detail::ECP_PUB_PEM_MAX_BYTES);
}

void EcPublicKeyBase::VerifySign(const void * hashBuf, size_t hashSize, const BigNumberBase & r, const BigNumberBase & s) const
{
	auto& ecCtx = GetEcContext();

	EcGroup ecGrp = ecCtx.grp;

	CALL_MBEDTLS_C_FUNC(mbedtls_ecdsa_verify, ecGrp.Get(), static_cast<const uint8_t*>(hashBuf), hashSize, &(ecCtx.Q), r.Get(), s.Get());
}

void EcPublicKeyBase::ToPublicBinary(void * xPtr, size_t xSize, void * yPtr, size_t ySize) const
{
	auto& ecCtx = GetEcContext();

	const BigNumber ctxX = const_cast<mbedtls_mpi&>(ecCtx.Q.X);
	const BigNumber ctxY = const_cast<mbedtls_mpi&>(ecCtx.Q.Y);

	ctxX.InternalToBinary(xPtr, xSize);
	ctxY.InternalToBinary(yPtr, ySize);
}

void EcKeyPairBase::CheckHasPrivateKey(const mbedtls_ecp_keypair & ctx)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_check_privkey, &ctx.grp, &ctx.d)
}

EcKeyPairBase::EcKeyPairBase(EcKeyPairBase && rhs) :
	EcPublicKeyBase(std::forward<EcPublicKeyBase>(rhs))
{
}

EcKeyPairBase::EcKeyPairBase(EcKeyType ecType, RbgBase& rbg) :
	EcPublicKeyBase()
{
	mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*Get());

	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_gen_key, GetEcGroupId(ecType), ecp, &RbgBase::CallBack, &rbg);
}

EcKeyPairBase::EcKeyPairBase(EcKeyType ecType, std::unique_ptr<RbgBase> rbg) :
	EcKeyPairBase(ecType, *rbg)
{
}

EcKeyPairBase::EcKeyPairBase(AsymKeyBase other) :
	EcPublicKeyBase(std::move(other))
{
	//EcPublicKeyBase has checked basic parameters.
	EcKeyPairBase::CheckHasPrivateKey(*mbedtls_pk_ec(*Get()));
}

EcKeyPairBase::EcKeyPairBase(AsymKeyBase & other) :
	EcPublicKeyBase(std::forward<AsymKeyBase>(CheckHasPrivateKey(other)))
{
}

EcKeyPairBase::EcKeyPairBase(mbedtls_pk_context & other) :
	EcPublicKeyBase(other)
{
	//EcPublicKeyBase has checked basic parameters.
	EcKeyPairBase::CheckHasPrivateKey(*mbedtls_pk_ec(*Get()));
}

EcKeyPairBase::EcKeyPairBase(const std::string & pem) :
	EcPublicKeyBase(pem)
{
	//EcPublicKeyBase has checked basic parameters.
	EcKeyPairBase::CheckHasPrivateKey(*mbedtls_pk_ec(*Get()));
}

EcKeyPairBase::EcKeyPairBase(const std::vector<uint8_t>& der) :
	EcPublicKeyBase(der)
{
	//EcPublicKeyBase has checked basic parameters.
	EcKeyPairBase::CheckHasPrivateKey(*mbedtls_pk_ec(*Get()));
}

EcKeyPairBase::EcKeyPairBase(EcKeyType ecType, const BigNumberBase & r, RbgBase& rbg) :
	EcPublicKeyBase(ecType)
{
	auto& ecCtx = GetEcContext();
	BigNumber ctxR = ecCtx.d;

	ctxR = r;

	//This will also check the private key:
	AsymKeyBase::CompletePublicKeyInContext(*mbedtls_pk_ec(*Get()), rbg);
}

EcKeyPairBase::EcKeyPairBase(EcKeyType ecType, const BigNumberBase & r, std::unique_ptr<RbgBase> rbg) :
	EcKeyPairBase(ecType, r, *rbg)
{
}

EcKeyPairBase::EcKeyPairBase(EcKeyType ecType, const BigNumberBase & r, const BigNumberBase & x, const BigNumberBase & y) :
	EcPublicKeyBase(ecType, x, y)
{
	auto& ecCtx = GetEcContext();
	BigNumber ctxR = ecCtx.d;

	ctxR = r;

	CALL_MBEDTLS_C_FUNC(mbedtls_ecp_check_privkey, &(ecCtx.grp), &(ecCtx.d));
}

EcKeyPairBase::~EcKeyPairBase()
{
}

AsymKeyBase & EcKeyPairBase::CheckHasPrivateKey(AsymKeyBase & other)
{
	EcPublicKeyBase::CheckIsAlgmTypeMatch(other.Get());
	EcKeyPairBase::CheckHasPrivateKey(*mbedtls_pk_ec(*other.Get()));
	return other;
}

EcKeyPairBase & EcKeyPairBase::operator=(EcKeyPairBase && rhs)
{
	EcPublicKeyBase::operator=(std::forward<EcPublicKeyBase>(rhs));
	return *this;
}

AsymKeyType EcKeyPairBase::GetKeyType() const
{
	return AsymKeyType::Private;
}

void EcKeyPairBase::GetPrivateDer(std::vector<uint8_t>& out) const
{
	return AsymKeyBase::GetPrivateDer(out, detail::ECP_PUB_DER_MAX_BYTES);
}

void EcKeyPairBase::GetPrivatePem(std::string & out) const
{
	return AsymKeyBase::GetPrivatePem(out, detail::ECP_PRV_PEM_MAX_BYTES);
}

void EcKeyPairBase::Sign(HashType hashType, const void * hashBuf, size_t hashSize, BigNumber & r, BigNumber & s, RbgBase& rbg) const
{
	if (!hashBuf)
	{
		throw MbedTlsException("mbedtls_ecdsa_sign(_det)", MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
	}

	auto& ecCtx = GetEcContext();

	EcGroup ecGrp = ecCtx.grp;

#ifdef MBEDTLS_ECDSA_DETERMINISTIC
	CALL_MBEDTLS_C_FUNC(mbedtls_ecdsa_sign_det, ecGrp.Get(), r.Get(), s.Get(),
		&ecCtx.d, static_cast<const uint8_t*>(hashBuf), hashSize, detail::GetMsgDigestType(hashType));
#else
	CALL_MBEDTLS_C_FUNC(mbedtls_ecdsa_sign, ecGrp.Get(), r.Get(), s.Get(),
		&ecCtx.d, static_cast<const uint8_t*>(hashBuf), hashSize, &RbgBase::CallBack, &rbg);
#endif
}

void EcKeyPairBase::Sign(HashType hashType, const void * hashBuf, size_t hashSize, void * rPtr, size_t rSize, void * sPtr, size_t sSize, RbgBase& rbg) const
{
	BigNumber r;
	BigNumber s;

	EcKeyPairBase::Sign(hashType, hashBuf, hashSize, r, s, rbg);

	r.InternalToBinary(rPtr, rSize);
	s.InternalToBinary(sPtr, sSize);
}

void EcKeyPairBase::ToPrivateBinary(void * rPtr, size_t rSize) const
{
	auto& ecCtx = GetEcContext();

	const BigNumber ctxR = const_cast<mbedtls_mpi&>(ecCtx.d);

	ctxR.InternalToBinary(rPtr, rSize);
}

void EcKeyPairBase::DeriveSharedKey(BigNumber & key, const EcPublicKeyBase & pubKey, RbgBase& rbg) const
{
	auto& ecCtx = GetEcContext();
	auto& pubEcCtx = pubKey.GetEcContext();

	EcGroup ecGrp = ecCtx.grp;

	CALL_MBEDTLS_C_FUNC(mbedtls_ecdh_compute_shared, ecGrp.Get(), key.Get(),
		&(pubEcCtx.Q), &ecCtx.d,
		&RbgBase::CallBack, &rbg);
}

void EcKeyPairBase::DeriveSharedKey(BigNumber & key, const EcPublicKeyBase & pubKey, std::unique_ptr<RbgBase> rbg) const
{
	return DeriveSharedKey(key, pubKey, *rbg);
}

void EcKeyPairBase::DeriveSharedKey(void * keyPtr, size_t keySize, const EcPublicKeyBase & pubKey, RbgBase& rbg) const
{
	BigNumber key;

	DeriveSharedKey(key, pubKey, rbg);

	key.InternalToBinary(keyPtr, keySize);
}

void EcKeyPairBase::DeriveSharedKey(void * keyPtr, size_t keySize, const EcPublicKeyBase & pubKey, std::unique_ptr<RbgBase> rbg) const
{
	return DeriveSharedKey(keyPtr, keySize, pubKey, *rbg);
}
