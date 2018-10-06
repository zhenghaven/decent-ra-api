#include "MbedTlsObjects.h"

#include <memory>

#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../common/MbedTlsHelpers.h"

#ifdef ENCLAVE_ENVIRONMENT

namespace std
{
	template<class T, size_t Size>
	inline reverse_iterator<T *> rbegin(T(&_Array)[Size])
	{	// get beginning of reversed array
		return (reverse_iterator<T *>(_Array + Size));
	}

	template<class T, size_t Size>
	inline reverse_iterator<T *> rend(T(&_Array)[Size])
	{	// get end of reversed array
		return (reverse_iterator<T *>(_Array));
	}
}

#endif // ENCLAVE_ENVIRONMENT

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;

	static constexpr mbedtls_ecp_group_id SECP256R1_CURVE_ID = mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1;

	static constexpr char const PEM_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
	static constexpr char const PEM_END_PUBLIC_KEY[] = "-----END PUBLIC KEY-----\n";

	//static constexpr char const PEM_BEGIN_PRIVATE_KEY_RSA[] = "-----BEGIN RSA PRIVATE KEY-----\n";
	//static constexpr char const PEM_END_PRIVATE_KEY_RSA[] = "-----END RSA PRIVATE KEY-----\n";
	static constexpr char const PEM_BEGIN_PRIVATE_KEY_EC[] = "-----BEGIN EC PRIVATE KEY-----\n";
	static constexpr char const PEM_END_PRIVATE_KEY_EC[] = "-----END EC PRIVATE KEY-----\n";

	static constexpr size_t ECP_PUB_DER_MAX_BYTES = (30 + 2 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t ECP_PRV_DER_MAX_BYTES = (29 + 3 * MBEDTLS_ECP_MAX_BYTES);

	static constexpr size_t ECP_PUB_PEM_MAX_BYTES = sizeof(PEM_BEGIN_PUBLIC_KEY) +
		cppcodec::base64_rfc4648::encoded_size(ECP_PUB_DER_MAX_BYTES) + 
		(cppcodec::base64_rfc4648::encoded_size(ECP_PUB_DER_MAX_BYTES) / 64) +
		sizeof(PEM_END_PUBLIC_KEY) +
		1;

	static constexpr size_t ECP_PRV_PEM_MAX_BYTES = sizeof(PEM_BEGIN_PRIVATE_KEY_EC) +
		cppcodec::base64_rfc4648::encoded_size(ECP_PRV_DER_MAX_BYTES) +
		(cppcodec::base64_rfc4648::encoded_size(ECP_PRV_DER_MAX_BYTES) / 64) +
		sizeof(PEM_END_PRIVATE_KEY_EC) +
		1;
}

static mbedtls_pk_context* ConstructEcPubFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
	mbedtls_pk_init(res.get());

	if (mbedtls_pk_parse_public_key(res.get(), ptr, size)
		!= MBEDTLS_SUCCESS_RET)
	{
		return nullptr;
	}

	if (mbedtls_pk_get_type(res.get()) != mbedtls_pk_type_t::MBEDTLS_PK_ECKEY)
	{
		return nullptr;
	}

	return res.release();
}

static mbedtls_pk_context* ConstructEcPubFromPem(const std::string & pemStr)
{
	return ConstructEcPubFromPemDer(reinterpret_cast<const uint8_t*>(pemStr.c_str()), pemStr.size() + 1);
}

static bool SetEcPubFromGeneral(const mbedtls_ecp_group& grp, mbedtls_ecp_point& dest, const general_secp256r1_public_t & pub)
{
	std::vector<uint8_t> tmpBuf(std::rbegin(pub.x), std::rend(pub.x));
	if (mbedtls_mpi_read_binary(&dest.X, tmpBuf.data(), tmpBuf.size()) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}

	tmpBuf.assign(std::rbegin(pub.y), std::rend(pub.y));

	return (mbedtls_mpi_read_binary(&dest.Y, tmpBuf.data(), tmpBuf.size()) == MBEDTLS_SUCCESS_RET) &&
		(mbedtls_mpi_lset(&dest.Z, 1) == MBEDTLS_SUCCESS_RET) &&
		(mbedtls_ecp_check_pubkey(&grp, &dest) == MBEDTLS_SUCCESS_RET);
}

static mbedtls_pk_context* ConstructEcPubFromGeneral(const general_secp256r1_public_t & pub)
{
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
	mbedtls_pk_init(res.get());

	mbedtls_ecp_keypair* ecPtr = nullptr;

	if (mbedtls_pk_setup(res.get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY))
		!= MBEDTLS_SUCCESS_RET ||
		!(ecPtr = mbedtls_pk_ec(*res)) ||
		mbedtls_ecp_group_load(&ecPtr->grp, SECP256R1_CURVE_ID) != MBEDTLS_SUCCESS_RET ||
		!SetEcPubFromGeneral(ecPtr->grp, ecPtr->Q, pub))
	{
		mbedtls_pk_free(res.get());
		return nullptr;
	}

	return res.release();
}

MbedECKeyPublic::MbedECKeyPublic(mbedtls_pk_context * m_ptr, bool isOwner) :
	MbedTlsObjBase(m_ptr),
	m_isOwner(isOwner)
{
}

MbedECKeyPublic::MbedECKeyPublic(const general_secp256r1_public_t & pub) :
	MbedECKeyPublic(ConstructEcPubFromGeneral(pub), true)
{
}

MbedECKeyPublic::MbedECKeyPublic(const std::string & pemStr) :
	MbedECKeyPublic(ConstructEcPubFromPem(pemStr), true)
{
}

MbedECKeyPublic::MbedECKeyPublic(MbedECKeyPublic && other) :
	MbedTlsObjBase(std::forward<MbedTlsObjBase>(other)),
	m_isOwner(other.m_isOwner)
{
	other.m_isOwner = false;
}

MbedECKeyPublic::~MbedECKeyPublic()
{
	if (*this && m_isOwner)
	{
		mbedtls_pk_free(m_ptr);
		delete m_ptr;
	}
}

MbedECKeyPublic & MbedECKeyPublic::operator=(MbedECKeyPublic && other)
{
	if (this != &other)
	{
		MbedTlsObjBase::operator=(std::forward<MbedTlsObjBase>(other));
		this->m_isOwner = other.m_isOwner;
		other.m_isOwner = false;
	}
	return *this;
}

std::string MbedECKeyPublic::ToPubPemString() const
{
	if (!*this)
	{
		return std::string();
	}
	
	std::vector<char> tmpRes(ECP_PUB_PEM_MAX_BYTES);
	if (mbedtls_pk_write_pubkey_pem(m_ptr, reinterpret_cast<unsigned char*>(tmpRes.data()), tmpRes.size())
		!= MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	return std::string(tmpRes.data());
}

bool MbedECKeyPublic::ToPubDerArray(std::vector<uint8_t>& outArray) const
{
	if (!*this)
	{
		return false;
	}

	outArray.resize(ECP_PUB_DER_MAX_BYTES);
	int len = mbedtls_pk_write_pubkey_der(m_ptr, outArray.data(), outArray.size());
	if (len <= 0)
	{
		return false;
	}

	outArray.resize(len);

	return true;
}

mbedtls_ecp_keypair * MbedECKeyPublic::GetInternalECKey() const
{
	if (!*this)
	{
		return nullptr;
	}
	return mbedtls_pk_ec(*m_ptr);
}

static mbedtls_pk_context* ConstructEcPrvFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
	mbedtls_pk_init(res.get());

	if (mbedtls_pk_parse_key(res.get(), ptr, size, nullptr, 0)
		!= MBEDTLS_SUCCESS_RET)
	{
		return nullptr;
	}

	if (mbedtls_pk_get_type(res.get()) != mbedtls_pk_type_t::MBEDTLS_PK_ECKEY)
	{
		return nullptr;
	}

	return res.release();
}

static mbedtls_pk_context* ConstructEcPrvFromPem(const std::string & pemStr)
{
	return ConstructEcPrvFromPemDer(reinterpret_cast<const uint8_t*>(pemStr.c_str()), pemStr.size() + 1);
}

MbedECKeyPair::MbedECKeyPair(mbedtls_pk_context * m_ptr, bool isOwner) :
	MbedECKeyPublic(m_ptr, isOwner)
{
}

static bool CheckPublicAndPrivatePair(const mbedtls_ecp_keypair* pair)
{
	mbedtls_ecp_point Q;
	mbedtls_ecp_group grp;

	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_group_init(&grp);

	mbedtls_ecp_group_copy(&grp, &pair->grp);

	void* drbgCtx;
	MbedTlsHelper::MbedTlsHelperDrbgInit(drbgCtx);
	int mbedRet = mbedtls_ecp_mul(&grp, &Q, &pair->d, &grp.G, &MbedTlsHelper::MbedTlsHelperDrbgRandom, drbgCtx);
	MbedTlsHelper::MbedTlsHelperDrbgFree(drbgCtx);

	bool negRes = (mbedRet != MBEDTLS_SUCCESS_RET) ||
		mbedtls_mpi_cmp_mpi(&Q.X, &pair->Q.X) ||
		mbedtls_mpi_cmp_mpi(&Q.Y, &pair->Q.Y) ||
		mbedtls_mpi_cmp_mpi(&Q.Z, &pair->Q.Z);

	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);

	return !negRes;
}

static mbedtls_pk_context* ConstructEcPrvFromGeneral(const general_secp256r1_private_t & prv, const general_secp256r1_public_t* pubPtr)
{
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
	mbedtls_pk_init(res.get());

	mbedtls_ecp_keypair* ecPtr = nullptr;

	std::vector<uint8_t> tmpBuf(std::rbegin(prv.r), std::rend(prv.r));
	if (mbedtls_pk_setup(res.get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY))
		!= MBEDTLS_SUCCESS_RET ||
		!(ecPtr = mbedtls_pk_ec(*res)) ||
		mbedtls_ecp_group_load(&ecPtr->grp, SECP256R1_CURVE_ID) != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_read_binary(&ecPtr->d, tmpBuf.data(), tmpBuf.size()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_ecp_check_privkey(&ecPtr->grp, &ecPtr->d) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_pk_free(res.get());
		return nullptr;
	}

	if (pubPtr)
	{
		if (!SetEcPubFromGeneral(ecPtr->grp, ecPtr->Q, *pubPtr) ||
			!CheckPublicAndPrivatePair(ecPtr))
		{
			mbedtls_pk_free(res.get());
			return nullptr;
		}
	}
	else
	{
		void* drbgCtx;
		MbedTlsHelper::MbedTlsHelperDrbgInit(drbgCtx);
		int mbedRet = mbedtls_ecp_mul(&ecPtr->grp, &ecPtr->Q, &ecPtr->d, &ecPtr->grp.G, &MbedTlsHelper::MbedTlsHelperDrbgRandom, drbgCtx);
		MbedTlsHelper::MbedTlsHelperDrbgFree(drbgCtx);
		if (mbedRet != MBEDTLS_SUCCESS_RET)
		{
			mbedtls_pk_free(res.get());
			return nullptr;
		}
	}

	return res.release();
}

MbedECKeyPair::MbedECKeyPair(const general_secp256r1_private_t & prv) :
	MbedECKeyPublic(ConstructEcPrvFromGeneral(prv, nullptr), true)
{
}

MbedECKeyPair::MbedECKeyPair(const general_secp256r1_private_t & prv, const general_secp256r1_public_t & pub) :
	MbedECKeyPublic(ConstructEcPrvFromGeneral(prv, &pub), true)
{
}

MbedECKeyPair::MbedECKeyPair(const std::string & pemStr) :
	MbedECKeyPair(ConstructEcPrvFromPem(pemStr), true)
{
}

MbedECKeyPair::~MbedECKeyPair()
{
	//if (*this && m_isOwner)
	//{
	//	mbedtls_pk_free(m_ptr);
	//	delete m_ptr;
	//}
}

std::string MbedECKeyPair::ToPrvPemString() const
{
	if (!*this)
	{
		return std::string();
	}

	std::vector<char> tmpRes(ECP_PRV_PEM_MAX_BYTES);
	if (mbedtls_pk_write_key_pem(m_ptr, reinterpret_cast<unsigned char*>(tmpRes.data()), tmpRes.size())
		!= MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	return std::string(tmpRes.data());
}

bool MbedECKeyPair::ToPrvDerArray(std::vector<uint8_t>& outArray) const
{
	if (!*this)
	{
		return false;
	}

	outArray.resize(ECP_PRV_DER_MAX_BYTES);
	int len = mbedtls_pk_write_key_der(m_ptr, outArray.data(), outArray.size());
	if (len <= 0)
	{
		return false;
	}

	outArray.resize(len);

	return true;
}
