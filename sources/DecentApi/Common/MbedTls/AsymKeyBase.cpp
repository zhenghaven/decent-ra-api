#include "AsymKeyBase.h"

#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/ecp.h>
#include <mbedtls/rsa.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>

#include "RbgBase.h"
#include "SafeWrappers.h"
#include "MbedTlsException.h"
#include "Internal/Hasher.h"
#include "Internal/AsymKeyBase.h"
#include "Internal/Asn1SizeEstimators.h"

using namespace Decent::MbedTlsObj;

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			inline size_t pk_write_rsa_pubkey_est_size(mbedtls_rsa_context *rsa)
			{
				size_t len = 0;

				/* Export E */
				const mbedtls_mpi& E = rsa->E;
				len += mbedtls_asn1_write_mpi_est_size(E);

				/* Export N */
				const mbedtls_mpi& N = rsa->N;
				len += mbedtls_asn1_write_mpi_est_size(E);
				
				len += mbedtls_asn1_write_len_est_size(len);
				len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

				return len;
			}


			inline size_t mbedtls_ecp_point_write_binary_est_size(
				const mbedtls_ecp_group *grp, const mbedtls_ecp_point *P, int format)
			{
				/*
				 * Common case: P == 0
				 */
				if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0)
				{
					return 1;
				}

				size_t plen = mbedtls_mpi_size(&grp->P);

				if (format == MBEDTLS_ECP_PF_UNCOMPRESSED)
				{
					return 2 * plen + 1;
				}
				else if (format == MBEDTLS_ECP_PF_COMPRESSED)
				{
					return plen + 1;
				}

				throw MbedTlsException("mbedtls_ecp_point_write_binary_est_size", MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
			}

			inline size_t pk_write_ec_pubkey_est_size(mbedtls_ecp_keypair *ec)
			{
				return mbedtls_ecp_point_write_binary_est_size(&ec->grp, &ec->Q,
					MBEDTLS_ECP_PF_UNCOMPRESSED);
			}

			inline size_t mbedtls_pk_write_pubkey_est_size(const mbedtls_pk_context *key)
			{
				size_t len = 0;

#if defined(MBEDTLS_RSA_C)
				if (mbedtls_pk_get_type(key) == MBEDTLS_PK_RSA)
					len += pk_write_rsa_pubkey_est_size(mbedtls_pk_rsa(*key));
				else
#endif
#if defined(MBEDTLS_ECP_C)
				if (mbedtls_pk_get_type(key) == MBEDTLS_PK_ECKEY)
					len += pk_write_ec_pubkey_est_size(mbedtls_pk_ec(*key));
				else
#endif
					throw MbedTlsException("mbedtls_pk_write_pubkey_est_size", MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);

				return len;
			}

			inline size_t pk_write_ec_param_est_size(mbedtls_ecp_keypair *ec)
			{
				const char *oid;
				size_t oid_len;

				CALL_MBEDTLS_C_FUNC(mbedtls_oid_get_oid_by_ec_grp, ec->grp.id, &oid, &oid_len);

				return mbedtls_asn1_write_oid_est_size(oid, oid_len);
			}

			inline size_t ec_signature_to_asn1_est_size(size_t rMaxSize, size_t sMaxSize)
			{
				size_t len = 0;

				len += mbedtls_asn1_write_mpi_est_size(sMaxSize);
				len += mbedtls_asn1_write_mpi_est_size(rMaxSize);

				len += mbedtls_asn1_write_len_est_size(len);
				len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

				return len;
			}
		}
	}
}

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

size_t AsymKeyBase::EstimatePublicKeyDerSize(const mbedtls_pk_context & key)
{
	using namespace detail;

	size_t len = 0, par_len = 0, oid_len = 0;
	const char *oid;

	len += mbedtls_pk_write_pubkey_est_size(&key);

	/*
	 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
	 *       algorithm            AlgorithmIdentifier,
	 *       subjectPublicKey     BIT STRING }
	 */

	len += 1;

	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING);

	CALL_MBEDTLS_C_FUNC(mbedtls_oid_get_oid_by_pk_alg, mbedtls_pk_get_type(&key), &oid, &oid_len);

#if defined(MBEDTLS_ECP_C)
	if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
	{
		par_len += pk_write_ec_param_est_size(mbedtls_pk_ec(key));
	}
#endif

	len += mbedtls_asn1_write_algorithm_identifier_est_size(oid, oid_len, par_len);

	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	return len;
}

size_t AsymKeyBase::EstimatePrivateKeyDerSize(const mbedtls_pk_context & key)
{
	using namespace detail;
	
	size_t len = 0;

#if defined(MBEDTLS_RSA_C)
	if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA)
	{
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

		/*
		 * Export the parameters one after another to avoid simultaneous copies.
		 */

		/* Export QP */
		const mbedtls_mpi& QP = rsa->QP;
		len += mbedtls_asn1_write_mpi_est_size(QP);

		/* Export DQ */
		const mbedtls_mpi& DQ = rsa->DQ;
		len += mbedtls_asn1_write_mpi_est_size(DQ);

		/* Export DP */
		const mbedtls_mpi& DP = rsa->DP;
		len += mbedtls_asn1_write_mpi_est_size(DP);

		/* Export Q */
		const mbedtls_mpi& Q = rsa->Q;
		len += mbedtls_asn1_write_mpi_est_size(Q);

		/* Export P */
		const mbedtls_mpi& P = rsa->P;
		len += mbedtls_asn1_write_mpi_est_size(P);

		/* Export D */
		const mbedtls_mpi& D = rsa->D;
		len += mbedtls_asn1_write_mpi_est_size(D);

		/* Export E */
		const mbedtls_mpi& E = rsa->E;
		len += mbedtls_asn1_write_mpi_est_size(E);

		/* Export N */
		const mbedtls_mpi& N = rsa->N;
		len += mbedtls_asn1_write_mpi_est_size(N);

		len += mbedtls_asn1_write_int_est_size(0);
		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	}
	else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
	if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
	{
		mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);
		size_t pub_len = 0, par_len = 0;

			/* publicKey */
		pub_len += pk_write_ec_pubkey_est_size(ec);

		pub_len += 1;

		pub_len += mbedtls_asn1_write_len_est_size(pub_len);
		pub_len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING);

		pub_len += mbedtls_asn1_write_len_est_size(pub_len);
		pub_len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1);
		len += pub_len;

		/* parameters */
		par_len += pk_write_ec_param_est_size(ec);

		par_len += mbedtls_asn1_write_len_est_size(par_len);
		par_len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0);
		len += par_len;

		/* privateKey: write as MPI then fix tag */
		len += mbedtls_asn1_write_mpi_est_size(ec->d);

		/* version */
		len += mbedtls_asn1_write_int_est_size(1);

		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	}
	else
#endif /* MBEDTLS_ECP_C */
		throw MbedTlsException("EstimatePrivateKeyDerSize", MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);

	return len;
}

size_t AsymKeyBase::EstimateDerSignatureSize(const mbedtls_pk_context & ctx, size_t hashLen)
{
	switch (mbedtls_pk_get_type(&ctx))
	{
	case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY:
	case mbedtls_pk_type_t::MBEDTLS_PK_ECDSA:
	{
		mbedtls_ecp_keypair* ec = mbedtls_pk_ec(ctx);

		size_t nBytes = (ec->grp.nbits + 7) >> 3;

		return detail::ec_signature_to_asn1_est_size(nBytes, nBytes);
	}
	case mbedtls_pk_type_t::MBEDTLS_PK_RSA:
	{
		mbedtls_rsa_context* rsa = static_cast<mbedtls_rsa_context*>(ctx.pk_ctx);
		return mbedtls_rsa_get_len(rsa);
	}
	case mbedtls_pk_type_t::MBEDTLS_PK_RSA_ALT:
	{
		mbedtls_rsa_alt_context* rsa_alt = static_cast<mbedtls_rsa_alt_context*>(ctx.pk_ctx);
		return rsa_alt->key_len_func(rsa_alt->key);
	}
	case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH:
	case mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS:
	case mbedtls_pk_type_t::MBEDTLS_PK_NONE:
	default:
		throw RuntimeException("Failed to estimate signature size. The given key type is not supported.");
	}
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
	return GetPublicDer(EstimatePublicKeyDerSize(*Get()));
}

std::string AsymKeyBase::GetPublicPem() const
{
	return GetPublicPem(EstimatePrivateKeyDerSize(*Get()));
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

std::vector<uint8_t> AsymKeyBase::GetPublicDer(size_t maxDerBufSize) const
{
	NullCheck();

	std::vector<uint8_t> der(maxDerBufSize);

	int len = mbedtls_pk_write_pubkey_der(GetMutable(), der.data(), der.size());
	if (len < 0)
	{
		throw Decent::MbedTlsObj::MbedTlsException("mbedtls_pk_write_pubkey_der", len);
	}

	size_t gap = der.size() - len;

	std::memmove(der.data(), der.data() + gap, len);

	der.resize(len);

	return der;
}

std::string AsymKeyBase::GetPublicPem(size_t maxDerBufSize) const
{
	using namespace detail;

	std::vector<uint8_t> der = GetPublicDer(maxDerBufSize);

	size_t pemLen = CalcPemMaxBytes(der.size(), PEM_PUBLIC_HEADER_SIZE, PEM_PUBLIC_FOOTER_SIZE);
	std::string pem(pemLen, '\0');

	size_t olen = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
		der.data(), der.size(),
		reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

	pem.resize(olen);

	return pem;
}

void AsymKeyBase::GetPrivateDer(std::vector<uint8_t>& out, size_t maxDerBufSize) const
{
	NullCheck();

	std::vector<uint8_t> der(maxDerBufSize);

	int len = mbedtls_pk_write_key_der(GetMutable(), der.data(), der.size());
	if (len <= 0)
	{
		throw Decent::MbedTlsObj::MbedTlsException("mbedtls_pk_write_pubkey_der", len);
	}

	out.resize(len);

	size_t gap = der.size() - len;

	std::memcpy(out.data(), der.data() + gap, len);

	ZeroizeContainer(der);
}

void AsymKeyBase::GetPrivatePem(std::string & out, size_t maxDerBufSize) const
{
	using namespace detail;

	std::vector<uint8_t> der;
	GetPrivateDer(der, maxDerBufSize);

	const char *begin = nullptr, *end = nullptr;
	size_t beginSize = 0, endSize = 0;

#if defined(MBEDTLS_RSA_C)
	if (mbedtls_pk_get_type(Get()) == MBEDTLS_PK_RSA)
	{
		begin = PEM_BEGIN_PRIVATE_KEY_RSA;
		end = PEM_END_PRIVATE_KEY_RSA;
		beginSize = PEM_RSA_PRIVATE_HEADER_SIZE;
		endSize = PEM_RSA_PRIVATE_FOOTER_SIZE;
	}
	else
#endif
#if defined(MBEDTLS_ECP_C)
	if (mbedtls_pk_get_type(Get()) == MBEDTLS_PK_ECKEY)
	{
		begin = PEM_BEGIN_PRIVATE_KEY_EC;
		end = PEM_END_PRIVATE_KEY_EC;
		beginSize = PEM_EC_PRIVATE_HEADER_SIZE;
		endSize = PEM_EC_PRIVATE_FOOTER_SIZE;
	}
	else
#endif
		throw MbedTlsException("GetPrivatePem", MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);

	size_t pemLen = CalcPemMaxBytes(der.size(), beginSize, endSize);
	std::string pem(pemLen, '\0');

	size_t olen = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, begin, end,
		der.data(), der.size(),
		reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

	out.resize(olen);

	std::memcpy(&out[0], pem.c_str(), olen);

	ZeroizeContainer(pem);
}
