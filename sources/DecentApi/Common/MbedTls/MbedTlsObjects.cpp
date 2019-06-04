#include "MbedTlsObjects.h"

#include <ctime>
#include <climits>

#include <memory>
#include <map>
#include <string>
#include <algorithm>

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pem.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "MbedTlsHelpers.h"
#include "MbedTlsInitializer.h"
#include "../Common.h"
#include "../make_unique.h"

//#include "BigNumber.h"
#include "Drbg.h"
#include "MbedTlsException.h"

#define CHECK_MBEDTLS_RET(VAL, FUNCSTR) {int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { throw MbedTlsException(#FUNCSTR, retVal); } }

using namespace Decent::MbedTlsObj;
using namespace Decent;

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
	static constexpr mbedtls_ecp_group_id SECP256R1_CURVE_ID = mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1;

	static constexpr char const PEM_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
	static constexpr char const PEM_END_PUBLIC_KEY[] = "-----END PUBLIC KEY-----\n";

	//static constexpr char const PEM_BEGIN_PRIVATE_KEY_RSA[] = "-----BEGIN RSA PRIVATE KEY-----\n";
	//static constexpr char const PEM_END_PRIVATE_KEY_RSA[] = "-----END RSA PRIVATE KEY-----\n";
	static constexpr char const PEM_BEGIN_PRIVATE_KEY_EC[] = "-----BEGIN EC PRIVATE KEY-----\n";
	static constexpr char const PEM_END_PRIVATE_KEY_EC[] = "-----END EC PRIVATE KEY-----\n";

	static constexpr char const PEM_BEGIN_CSR[] = "-----BEGIN CERTIFICATE REQUEST-----\n";
	static constexpr char const PEM_END_CSR[] = "-----END CERTIFICATE REQUEST-----\n";
	static constexpr char const PEM_BEGIN_CRT[] = "-----BEGIN CERTIFICATE-----\n";
	static constexpr char const PEM_END_CRT[] = "-----END CERTIFICATE-----\n";
	static constexpr char const PEM_BEGIN_CRL[] = "-----BEGIN X509 CRL-----\n";
	static constexpr char const PEM_END_CRL[] = "-----END X509 CRL-----\n";

	static constexpr size_t ECP_PUB_DER_MAX_BYTES = (30 + 2 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t ECP_PRV_DER_MAX_BYTES = (29 + 3 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t RSA_PUB_DER_MAX_BYTES = (38 + 2 * MBEDTLS_MPI_MAX_SIZE);
	static constexpr size_t X509_REQ_DER_MAX_BYTES = 4096; //From x509write_csr.c
	static constexpr size_t X509_CRT_DER_MAX_BYTES = 4096; //From x509write_crt.c

	static constexpr size_t PUB_DER_MAX_BYTES = ECP_PUB_DER_MAX_BYTES > RSA_PUB_DER_MAX_BYTES ? ECP_PUB_DER_MAX_BYTES : RSA_PUB_DER_MAX_BYTES;

	static constexpr size_t CalcPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
	{
		return headerSize + 
			cppcodec::base64_rfc4648::encoded_size(derMaxSize) + 1 + 
			(cppcodec::base64_rfc4648::encoded_size(derMaxSize) / 64) +  //'\n' for each line.
			footerSize + 
			1;                   //null terminator
	}

	static constexpr size_t ECP_PUB_PEM_MAX_BYTES = 
		CalcPemMaxBytes(ECP_PUB_DER_MAX_BYTES, sizeof(PEM_BEGIN_PUBLIC_KEY) - 1, sizeof(PEM_END_PUBLIC_KEY) - 1);

	static constexpr size_t RSA_PUB_PEM_MAX_BYTES = 
		CalcPemMaxBytes(RSA_PUB_DER_MAX_BYTES, sizeof(PEM_BEGIN_PUBLIC_KEY) - 1, sizeof(PEM_END_PUBLIC_KEY) - 1);

	static constexpr size_t PUB_PEM_MAX_BYTES = ECP_PUB_PEM_MAX_BYTES > RSA_PUB_PEM_MAX_BYTES ? ECP_PUB_PEM_MAX_BYTES : RSA_PUB_PEM_MAX_BYTES;

	static constexpr size_t ECP_PRV_PEM_MAX_BYTES =
		CalcPemMaxBytes(ECP_PRV_DER_MAX_BYTES, sizeof(PEM_BEGIN_PRIVATE_KEY_EC) - 1, sizeof(PEM_END_PRIVATE_KEY_EC) - 1);

	static constexpr size_t X509_REQ_PEM_MAX_BYTES =
		CalcPemMaxBytes(X509_REQ_DER_MAX_BYTES, sizeof(PEM_BEGIN_CSR) - 1, sizeof(PEM_END_CSR) - 1);

	static constexpr size_t X509_CRT_PEM_MAX_BYTES =
		CalcPemMaxBytes(X509_CRT_DER_MAX_BYTES, sizeof(PEM_BEGIN_CRT) - 1, sizeof(PEM_END_CRT) - 1);



	struct EcGroupWarp
	{
		mbedtls_ecp_group m_grp;

		EcGroupWarp()
		{
			mbedtls_ecp_group_init(&m_grp);
		}

		~EcGroupWarp()
		{
			mbedtls_ecp_group_free(&m_grp);
		}

		bool Copy(const mbedtls_ecp_group& grp)
		{
			return mbedtls_ecp_group_copy(&m_grp, &grp) == MBEDTLS_SUCCESS_RET;
		}
	};
}


void PKey::FreeObject(mbedtls_pk_context * ptr)
{
	mbedtls_pk_free(ptr);
	delete ptr;
}

bool PKey::VerifySignSha256(const General256Hash& hash, const void* sign, const size_t signLen) const
{
	if (!*this || !sign)
	{
		return false;
	}
	const uint8_t* signByte = static_cast<const uint8_t*>(sign);
	return mbedtls_pk_verify(Get(), mbedtls_md_type_t::MBEDTLS_MD_SHA256, hash.data(), hash.size(), signByte, signLen) == MBEDTLS_SUCCESS_RET;
}

PKey::PKey() :
	ObjBase(new mbedtls_pk_context, &FreeObject)
{
	mbedtls_pk_init(Get());
}

std::string PKey::ToPubPemString(const size_t maxBufSize) const
{
	if (!*this)
	{
		return std::string();
	}

	std::unique_ptr<char[]> buf = Tools::make_unique<char[]>(maxBufSize);
	if (mbedtls_pk_write_pubkey_pem(Get(), reinterpret_cast<unsigned char*>(buf.get()), maxBufSize)
		!= MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	return std::string(buf.get());
}

bool PKey::ToPubDerArray(std::vector<uint8_t>& outArray, const size_t maxBufSize) const
{
	if (!*this)
	{
		return false;
	}

	outArray.resize(maxBufSize);
	int len = mbedtls_pk_write_pubkey_der(Get(), outArray.data(), outArray.size());
	if (len <= 0)
	{
		outArray.resize(0);
		return false;
	}

	outArray.resize(len);
	return true;
}

std::string PKey::ToPubPemString() const
{
	return PKey::ToPubPemString(PUB_PEM_MAX_BYTES);
}

bool PKey::ToPubDerArray(std::vector<uint8_t>& outArray) const
{
	return PKey::ToPubDerArray(outArray, PUB_DER_MAX_BYTES);
}

ECKeyPublic ECKeyPublic::FromPemDer(const void* ptr, size_t size)
{
	ECKeyPublic res;

	if (mbedtls_pk_parse_public_key(res.Get(), static_cast<const uint8_t*>(ptr), size) != MBEDTLS_SUCCESS_RET ||
		!res)
	{
		return ECKeyPublic(nullptr, ObjBase::DoNotFree);
	}

	return res;
}

ECKeyPublic ECKeyPublic::FromPemString(const std::string & pemStr)
{
	return FromPemDer(pemStr.c_str(), pemStr.size() + 1);
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

ECKeyPublic ECKeyPublic::FromGeneral(const general_secp256r1_public_t & pub)
{
	ECKeyPublic res;

	mbedtls_ecp_keypair* ecPtr = nullptr;

	if (mbedtls_pk_setup(res.Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY))	!= MBEDTLS_SUCCESS_RET ||
		!(ecPtr = mbedtls_pk_ec(*res.Get())) ||
		mbedtls_ecp_group_load(&ecPtr->grp, SECP256R1_CURVE_ID) != MBEDTLS_SUCCESS_RET ||
		!SetEcPubFromGeneral(ecPtr->grp, ecPtr->Q, pub))
	{
		return ECKeyPublic(nullptr, ObjBase::DoNotFree);
	}

	return res;
}

ECKeyPublic::operator bool() const noexcept
{
	return PKey::operator bool() &&
		mbedtls_pk_get_type(Get()) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY;
}

bool ECKeyPublic::ToGeneralPubKey(general_secp256r1_public_t & outKey) const
{
	if (!*this)
	{
		return false;
	}
	
	const mbedtls_ecp_keypair& ecPtr = *GetEcKeyPtr();
	
	if (mbedtls_mpi_write_binary(&ecPtr.Q.X, outKey.x, sizeof(outKey.x)) != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_write_binary(&ecPtr.Q.Y, outKey.y, sizeof(outKey.y)) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}
	
	std::reverse(std::begin(outKey.x), std::end(outKey.x));
	std::reverse(std::begin(outKey.y), std::end(outKey.y));
	
	return true;
}

std::unique_ptr<general_secp256r1_public_t> ECKeyPublic::ToGeneralPubKey() const
{
	std::unique_ptr<general_secp256r1_public_t> pubKey = Tools::make_unique<general_secp256r1_public_t>();
	if (!pubKey || !ToGeneralPubKey(*pubKey))
	{
		return nullptr;
	}
	return std::move(pubKey);
}

general_secp256r1_public_t ECKeyPublic::ToGeneralPubKeyChecked() const
{
	general_secp256r1_public_t pubKey;
	ToGeneralPubKey(pubKey);
	return pubKey;
}

bool ECKeyPublic::VerifySign(const general_secp256r1_signature_t & inSign, const uint8_t * hash, const size_t hashLen) const
{
	if (!*this || !hash || hashLen <= 0)
	{
		return false;
	}
	const ConstBigNumber r(inSign.x);
	const ConstBigNumber s(inSign.y);
	EcGroupWarp grp;

	const mbedtls_ecp_keypair& ecPtr = *GetEcKeyPtr();

	if (!grp.Copy(ecPtr.grp))
	{
		return false;
	}

	return mbedtls_ecdsa_verify(&grp.m_grp, hash, hashLen, &ecPtr.Q,
		r.Get().Get(), s.Get().Get()) == MBEDTLS_SUCCESS_RET;
}

std::string ECKeyPublic::ToPubPemString() const
{
	return PKey::ToPubPemString(ECP_PUB_PEM_MAX_BYTES);
}

bool ECKeyPublic::ToPubDerArray(std::vector<uint8_t>& outArray) const
{
	return PKey::ToPubDerArray(outArray, ECP_PUB_DER_MAX_BYTES);
}

mbedtls_ecp_keypair * ECKeyPublic::GetEcKeyPtr()
{
	return *this ? mbedtls_pk_ec(*Get()) : nullptr;
}

const mbedtls_ecp_keypair * ECKeyPublic::GetEcKeyPtr() const
{
	return *this ? mbedtls_pk_ec(*Get()) : nullptr;
}

ECKeyPair ECKeyPair::FromPemDer(const void* ptr, size_t size)
{
	ECKeyPair res;

	if (mbedtls_pk_parse_key(res.Get(), static_cast<const uint8_t*>(ptr), size, nullptr, 0) != MBEDTLS_SUCCESS_RET ||
		!res)
	{
		return ECKeyPair(nullptr, ObjBase::DoNotFree);
	}

	return res;
}

ECKeyPair ECKeyPair::FromPemString(const std::string & pemStr)
{
	return FromPemDer(pemStr.c_str(), pemStr.size() + 1);
}

static bool CheckPublicAndPrivatePair(const mbedtls_ecp_keypair* pair)
{
	mbedtls_ecp_point Q;
	mbedtls_ecp_group grp;

	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_group_init(&grp);

	mbedtls_ecp_group_copy(&grp, &pair->grp);

	Drbg drbg;
	int mbedRet = mbedtls_ecp_mul(&grp, &Q, &pair->d, &grp.G, &Drbg::CallBack, &drbg);

	bool negRes = (mbedRet != MBEDTLS_SUCCESS_RET) ||
		mbedtls_mpi_cmp_mpi(&Q.X, &pair->Q.X) ||
		mbedtls_mpi_cmp_mpi(&Q.Y, &pair->Q.Y) ||
		mbedtls_mpi_cmp_mpi(&Q.Z, &pair->Q.Z);

	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);

	return !negRes;
}

ECKeyPair ECKeyPair::FromGeneral(const general_secp256r1_private_t & prv, const general_secp256r1_public_t* pubPtr)
{
	ECKeyPair res;
	ECKeyPair fail(nullptr, ObjBase::DoNotFree);

	mbedtls_ecp_keypair* ecPtr = nullptr;

	std::vector<uint8_t> tmpBuf(std::rbegin(prv.r), std::rend(prv.r));
	if (mbedtls_pk_setup(res.Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY))
		!= MBEDTLS_SUCCESS_RET ||
		!(ecPtr = mbedtls_pk_ec(*res.Get())) ||
		mbedtls_ecp_group_load(&ecPtr->grp, SECP256R1_CURVE_ID) != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_read_binary(&ecPtr->d, tmpBuf.data(), tmpBuf.size()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_ecp_check_privkey(&ecPtr->grp, &ecPtr->d) != MBEDTLS_SUCCESS_RET)
	{
		return fail;
	}

	if (pubPtr)
	{
		if (!SetEcPubFromGeneral(ecPtr->grp, ecPtr->Q, *pubPtr) ||
			!CheckPublicAndPrivatePair(ecPtr))
		{
			return fail;
		}
	}
	else
	{
		Drbg drbg;
		if (mbedtls_ecp_mul(&ecPtr->grp, &ecPtr->Q, &ecPtr->d, &ecPtr->grp.G, &Drbg::CallBack, &drbg)
			!= MBEDTLS_SUCCESS_RET)
		{
			return fail;
		}
	}

	return res;
}

ECKeyPair ECKeyPair::GenerateNewKey()
{
	ECKeyPair res;

	Drbg drbg;

	CHECK_MBEDTLS_RET(mbedtls_pk_setup(res.Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY)), ECKeyPair::GenerateNewKey);

	mbedtls_ecp_keypair* ecPtr = mbedtls_pk_ec(*res.Get());
	if (!ecPtr)
	{
		throw RuntimeException("In ECKeyPair::GenerateNewKey, failed to retrieve EC key pointer.");
	}

	CHECK_MBEDTLS_RET(mbedtls_ecp_gen_key(SECP256R1_CURVE_ID, ecPtr, &Drbg::CallBack, &drbg), ECKeyPair::GenerateNewKey);
	
	return res;
}

bool ECKeyPair::ToGeneralPrvKey(PrivateKeyWrap & outKey) const
{
	if (!*this)
	{
		return false;
	}

	const mbedtls_ecp_keypair& ecPtr = *GetEcKeyPtr();
	if (mbedtls_mpi_write_binary(&ecPtr.d, outKey.m_prvKey.r, sizeof(outKey.m_prvKey.r)) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}
	std::reverse(std::begin(outKey.m_prvKey.r), std::end(outKey.m_prvKey.r));

	return true;
}

std::unique_ptr<PrivateKeyWrap> ECKeyPair::ToGeneralPrvKey() const
{
	std::unique_ptr<PrivateKeyWrap> prvKey = Tools::make_unique<PrivateKeyWrap>();
	if (!prvKey || !ToGeneralPrvKey(*prvKey))
	{
		return nullptr;
	}
	return std::move(prvKey);
}

PrivateKeyWrap ECKeyPair::ToGeneralPrvKeyChecked() const
{
	PrivateKeyWrap prvKey;
	if (ToGeneralPrvKey(prvKey))
	{
		return prvKey;
	}

	return PrivateKeyWrap();
}

bool ECKeyPair::GenerateSharedKey(General256BitKey & outKey, const ECKeyPublic & peerPubKey)
{
	if (!*this || !peerPubKey)
	{
		return false;
	}

	const mbedtls_ecp_keypair& ecPtr = *GetEcKeyPtr();
	BigNumber sharedKey(sk_empty);
	EcGroupWarp grp;
	if (!grp.Copy(ecPtr.grp))
	{
		return false;
	}

	Drbg drbg;

	int mbedRet = mbedtls_ecdh_compute_shared(&grp.m_grp, sharedKey.Get(),
		&peerPubKey.GetEcKeyPtr()->Q, &ecPtr.d,
		&Drbg::CallBack, &drbg);

	if (mbedRet != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_size(sharedKey.Get()) != outKey.size() ||
		mbedtls_mpi_write_binary(sharedKey.Get(), outKey.data(), outKey.size()) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}

	std::reverse(outKey.begin(), outKey.end());

	return true;
}

bool ECKeyPair::EcdsaSign(general_secp256r1_signature_t & outSign, const uint8_t * hash, const size_t hashLen, const mbedtls_md_info_t* mdInfo) const
{
	if (!*this || !hash || !mdInfo || hashLen != mdInfo->size)
	{
		return false;
	}

	int mbedRet = 0;
	BigNumber r(sk_empty);
	BigNumber s(sk_empty);
	EcGroupWarp grp;
	const mbedtls_ecp_keypair& ecPtr = *GetEcKeyPtr();

	if (!grp.Copy(ecPtr.grp))
	{
		return false;
	}

#ifdef MBEDTLS_ECDSA_DETERMINISTIC
	mbedRet = mbedtls_ecdsa_sign_det(&grp.m_grp, r.Get(), s.Get(), 
		&ecPtr.d, hash, hashLen, mdInfo->type);
#else
	Drbg drbg;
	mbedRet = mbedtls_ecdsa_sign(&grp.m_grp, r.Get(), s.Get(),
		&ecPtr.d, hash, hashLen, &Drbg::CallBack, &drbg);
#endif 

	if (mbedRet != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}
	
	r.ToBinary(outSign.x, sk_struct);
	s.ToBinary(outSign.y, sk_struct);

	return true;
}

std::string ECKeyPair::ToPrvPemString() const
{
	if (!*this)
	{
		return std::string();
	}

	std::vector<char> tmpRes(ECP_PRV_PEM_MAX_BYTES);
	if (mbedtls_pk_write_key_pem(Get(), reinterpret_cast<unsigned char*>(tmpRes.data()), tmpRes.size())
		!= MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	return std::string(tmpRes.data());
}

bool ECKeyPair::ToPrvDerArray(std::vector<uint8_t>& outArray) const
{
	if (!*this)
	{
		return false;
	}

	outArray.resize(ECP_PRV_DER_MAX_BYTES);
	int len = mbedtls_pk_write_key_der(Get(), outArray.data(), outArray.size());
	if (len <= 0)
	{
		return false;
	}

	outArray.resize(len);

	return true;
}

X509Req X509Req::FromPemDer(const void* ptr, size_t size)
{
	X509Req res;

	const uint8_t* ptrByte = static_cast<const uint8_t*>(ptr);
	if(mbedtls_x509_csr_parse(res.Get(), ptrByte, size) != MBEDTLS_SUCCESS_RET)
	{
		return X509Req(nullptr, &ObjBase::DoNotFree);
	}

	return res;
}

X509Req X509Req::FromPem(const std::string & pemStr)
{
	return FromPemDer(pemStr.c_str(), pemStr.size() + 1);
}

static const std::string CreateX509Pem(const PKey & keyPair, const std::string& commonName)
{
	if (!keyPair)
	{
		return std::string();
	}

	mbedtls_x509write_csr csr;
	mbedtls_x509write_csr_init(&csr);

	mbedtls_x509write_csr_set_key(&csr, keyPair.Get());
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
	if (mbedtls_x509write_csr_set_subject_name(&csr, ("CN=" + commonName).c_str()) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509write_csr_free(&csr);
		return std::string();
	}

	Drbg drbg;

	std::vector<char> tmpRes(X509_REQ_PEM_MAX_BYTES);
	int mbedRet = mbedtls_x509write_csr_pem(&csr, 
		reinterpret_cast<unsigned char*>(tmpRes.data()), tmpRes.size(), 
		&Drbg::CallBack, &drbg);

	mbedtls_x509write_csr_free(&csr);
	return mbedRet == MBEDTLS_SUCCESS_RET ? std::string(tmpRes.data()) : std::string();
}

X509Req::X509Req(const std::string & pemStr) :
	X509Req(FromPem(pemStr))
{
}

void X509Req::FreeObject(mbedtls_x509_csr * ptr)
{
	mbedtls_x509_csr_free(ptr);
	delete ptr;
}

X509Req::X509Req(const PKey & keyPair, const std::string& commonName) :
	X509Req(CreateX509Pem(keyPair, commonName))
{
}

X509Req::operator bool() const noexcept
{
	return ObjBase::operator bool() && m_pubKey;
}

bool X509Req::VerifySignature() const
{
	if (!*this)
	{
		return false;
	}

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(Get()->sig_md);
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	bool verifyRes = 
		(mbedtls_md(mdInfo, Get()->cri.p, Get()->cri.len, hash) == MBEDTLS_SUCCESS_RET) &&
		(mbedtls_pk_verify_ext(Get()->sig_pk, Get()->sig_opts, &Get()->pk,
			Get()->sig_md, hash, mbedtls_md_get_size(mdInfo),
			Get()->sig.p, Get()->sig.len) == MBEDTLS_SUCCESS_RET);

	return verifyRes;
}

const PKey & X509Req::GetPublicKey() const
{
	return m_pubKey;
}

std::string X509Req::ToPemString() const
{
	size_t useLen = CalcPemMaxBytes(Get()->raw.len, sizeof(PEM_BEGIN_CSR) - 1, sizeof(PEM_END_CSR) - 1);
	
	std::string res(useLen, 0);
	if (mbedtls_pem_write_buffer(PEM_BEGIN_CSR, PEM_END_CSR, Get()->raw.p, Get()->raw.len, 
		reinterpret_cast<uint8_t*>(&res[0]), res.size(), &useLen) != MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	res.pop_back();
	return res;
}

X509Req::X509Req() :
	ObjBase(new mbedtls_x509_csr, &FreeObject),
	m_pubKey(Get()->pk)
{
	mbedtls_x509_csr_init(Get());
}

X509Req::X509Req(mbedtls_x509_csr * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc),
	m_pubKey(ptr ? ptr->pk : PKey::Empty())
{
}

static int x509_write_time(unsigned char **p, unsigned char *start,
	const char *t, size_t size)
{
	int ret;
	size_t len = 0;

	/*
	 * write MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
	 */
	if (t[0] == '2' && t[1] == '0' && t[2] < '5')
	{
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
			(const unsigned char *)t + 2,
			size - 2));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_UTC_TIME));
	}
	else
	{
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
			(const unsigned char *)t,
			size));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_GENERALIZED_TIME));
	}

	return((int)len);
}

static int myX509WriteCrtDer(mbedtls_x509write_cert *ctx, std::vector<uint8_t>& buf,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret;
	const char *sig_oid;
	size_t sig_oid_len = 0;
	unsigned char *c, *c2;
	unsigned char hash[64];
	unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
	size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
	size_t len = 0;
	mbedtls_pk_type_t pk_alg;

	c = buf.data() + buf.size();

	if (mbedtls_pk_can_do(ctx->issuer_key, MBEDTLS_PK_RSA))
		pk_alg = MBEDTLS_PK_RSA;
	else if (mbedtls_pk_can_do(ctx->issuer_key, MBEDTLS_PK_ECDSA))
		pk_alg = MBEDTLS_PK_ECDSA;
	else
		return(MBEDTLS_ERR_X509_INVALID_ALG);

	if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
		&sig_oid, &sig_oid_len)) != 0)
	{
		return(ret);
	}

	if (ctx->version == MBEDTLS_X509_CRT_VERSION_3)
	{
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_extensions(&c, buf.data(), ctx->extensions));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf.data(), len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf.data(), MBEDTLS_ASN1_CONSTRUCTED |
			MBEDTLS_ASN1_SEQUENCE));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf.data(), len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf.data(), MBEDTLS_ASN1_CONTEXT_SPECIFIC |
			MBEDTLS_ASN1_CONSTRUCTED | 3));
	}

	MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_pk_write_pubkey_der(ctx->subject_key, buf.data(), c - buf.data()));
	c -= pub_len;
	len += pub_len;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf.data(), ctx->subject));

	sub_len = 0;

	MBEDTLS_ASN1_CHK_ADD(sub_len, x509_write_time(&c, buf.data(), ctx->not_after,
		MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

	MBEDTLS_ASN1_CHK_ADD(sub_len, x509_write_time(&c, buf.data(), ctx->not_before,
		MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

	len += sub_len;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf.data(), sub_len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf.data(), MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_SEQUENCE));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf.data(), ctx->issuer));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, buf.data(),
		sig_oid, strlen(sig_oid), 0));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf.data(), &ctx->serial));

	if (ctx->version != MBEDTLS_X509_CRT_VERSION_1)
	{
		sub_len = 0;
		MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_int(&c, buf.data(), ctx->version));
		len += sub_len;
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf.data(), sub_len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf.data(), MBEDTLS_ASN1_CONTEXT_SPECIFIC |
			MBEDTLS_ASN1_CONSTRUCTED | 0));
	}

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf.data(), len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf.data(), MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_SEQUENCE));

	/*
	 * Make signature
	 */
	if ((ret = mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), c, len, hash)) != 0 ||
		(ret = mbedtls_pk_sign(ctx->issuer_key, ctx->md_alg, hash, 0, sig, &sig_len, f_rng, p_rng)) != 0)
	{
		return(ret);
	}

	/*
	 * Write data to output buffer
	 */
	std::vector<uint8_t> sigAndOid(sig_oid_len + sig_len + 128);
	c2 = sigAndOid.data() + sigAndOid.size();
	MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, sigAndOid.data(),
		sig_oid, sig_oid_len, sig, sig_len));

	buf.insert(buf.end(), sigAndOid.end() - sig_and_oid_len, sigAndOid.end());

	len += sig_and_oid_len;
	c2 = buf.data() + buf.size() - len;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c2, buf.data(), len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c2, buf.data(), MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_SEQUENCE));

	return((int)len);
}

static std::string GetFormatedTime(const time_t& timer)
{
	std::tm timeRes;
	Tools::GetSystemUtcTime(timer, timeRes);

	std::string res(sizeof("YYYYMMDDHHMMSS0"), '\0');

	strftime(&res[0], res.size(), "%Y%m%d%H%M%S", &timeRes);

	return res;
}

static std::string ConstructNewX509Cert(const X509Cert* caCert, const PKey& prvKey, const PKey& pubKey,
	const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
	const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap)
{
	//Check parameter.
	if (!prvKey || !pubKey)
	{
		return std::string();
	}
	
	const bool hasCa = caCert && *caCert;
	mbedtls_x509write_cert cert;
	mbedtls_x509write_crt_init(&cert);

	mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_issuer_key(&cert, prvKey.Get());
	mbedtls_x509write_crt_set_subject_key(&cert, pubKey.Get());

	time_t timerBegin;
	Tools::GetSystemTime(timerBegin);
	time_t timerEnd = validTime > (LONG_MAX - timerBegin) ? LONG_MAX : (timerBegin + validTime);

	if (mbedtls_x509write_crt_set_validity(&cert, GetFormatedTime(timerBegin).c_str(), GetFormatedTime(timerEnd).c_str()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_serial(&cert, serialNum.Get()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_subject_name(&cert, x509NameList.c_str()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_basic_constraints(&cert, isCa, maxChainDepth) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_key_usage(&cert, keyUsage) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_ns_cert_type(&cert, nsType) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509write_crt_free(&cert);
		return std::string();
	}

	size_t extTotalSize = 0;

	int mbedRet = hasCa ? MbedTlsHelper::MbedTlsAsn1DeepCopy(cert.issuer, caCert->Get()->subject) :
		(mbedtls_x509write_crt_set_issuer_name(&cert, x509NameList.c_str()) == MBEDTLS_SUCCESS_RET);
	for (auto it = extMap.begin(); it != extMap.end() && mbedRet; ++it)
	{
		mbedRet = mbedtls_x509write_crt_set_extension(&cert, it->first.c_str(), it->first.size(), it->second.first,
			reinterpret_cast<const unsigned char*>(it->second.second.c_str()), it->second.second.size()) == MBEDTLS_SUCCESS_RET;
		extTotalSize += it->second.second.size() + it->first.size();
	}
	if (!mbedRet)
	{
		mbedtls_x509write_crt_free(&cert);
		return std::string();
	}

	Drbg drbg;

	std::vector<uint8_t> tmpDerBuf(X509_CRT_DER_MAX_BYTES + extTotalSize + 5);

	mbedRet = myX509WriteCrtDer(&cert, tmpDerBuf,
		&Drbg::CallBack, &drbg);
	if (mbedRet < 0)
	{
		mbedtls_x509write_crt_free(&cert);
		return std::string();
	}
	std::vector<char> tmpRes(X509_CRT_PEM_MAX_BYTES + cppcodec::base64_rfc4648::encoded_size(extTotalSize) + (extTotalSize / 64));
	mbedRet = mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, 
		reinterpret_cast<const uint8_t*>(tmpDerBuf.data()) + tmpDerBuf.size() - mbedRet,
		mbedRet, reinterpret_cast<uint8_t*>(tmpRes.data()), tmpRes.size(), &extTotalSize);

	mbedtls_x509write_crt_free(&cert);
	return mbedRet == MBEDTLS_SUCCESS_RET ? std::string(tmpRes.data()) + (hasCa ? caCert->ToPemString() : std::string()) : std::string();
}

X509Cert X509Cert::FromPemDer(const void* ptr, size_t size)
{
	X509Cert res;

	const uint8_t* ptrByte = static_cast<const uint8_t*>(ptr);
	if (mbedtls_x509_crt_parse(res.Get(), ptrByte, size) != MBEDTLS_SUCCESS_RET)
	{
		return X509Cert(nullptr, &ObjBase::DoNotFree);
	}
	{
		int chainLen = 0;
		for (auto it = res.Get(); it != nullptr; ++chainLen, it = it->next);
		LOGI("Parsed X509 Chain with length %d.", chainLen);
	}

	return res;
}

X509Cert X509Cert::FromPem(const std::string & pemStr)
{
	return FromPemDer(pemStr.c_str(), pemStr.size() + 1);
}

void X509Cert::FreeObject(mbedtls_x509_crt * ptr)
{
	mbedtls_x509_crt_free(ptr);
	delete ptr;
}

X509Cert::X509Cert(const std::string & pemStr) :
	X509Cert(FromPem(pemStr))
{
}

X509Cert::X509Cert(mbedtls_x509_crt & ref) :
	ObjBase(&ref, &ObjBase::DoNotFree),
	m_pubKey(ref.pk)
{
}

X509Cert::X509Cert() :
	ObjBase(new mbedtls_x509_crt, &FreeObject),
	m_pubKey(Get()->pk)
{
	mbedtls_x509_crt_init(Get());
}

X509Cert::X509Cert(mbedtls_x509_crt * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc),
	m_pubKey(ptr ? ptr->pk : PKey::Empty())
{
}

X509Cert::X509Cert(const X509Cert & caCert, const PKey & prvKey, const PKey & pubKey,
	const BigNumber & serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
	const std::string & x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap) :
	X509Cert(ConstructNewX509Cert(&caCert, prvKey, pubKey, 
		serialNum, validTime, isCa, maxChainDepth, keyUsage, nsType,
		x509NameList, extMap))
{
}

X509Cert::X509Cert(const PKey & prvKey,
	const BigNumber & serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
	const std::string & x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap) :
	X509Cert(ConstructNewX509Cert(nullptr, prvKey, prvKey, 
		serialNum, validTime, isCa, maxChainDepth, keyUsage, nsType,
		x509NameList, extMap))
{
}

X509Cert::operator bool() const noexcept
{
	return ObjBase::operator bool() && m_pubKey;
}

bool X509Cert::GetExtensions(std::map<std::string, std::pair<bool, std::string> >& extMap) const
{
	if (!X509Cert::operator bool())
	{
		return false;
	}

	if (extMap.size() == 0)
	{
		return true;
	}

	int mbedRet = 0;
	int is_critical = 0;
	size_t len = 0;

	unsigned char *end_ext_data = nullptr;
	unsigned char *end_ext_octet = nullptr;

	unsigned char *begin = Get()->v3_ext.p;
	const unsigned char *end = Get()->v3_ext.p + Get()->v3_ext.len;

	unsigned char **p = &begin;

	if (mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != MBEDTLS_SUCCESS_RET ||
		(*p + len) != end)
	{
		return false;
	}

	while (*p < end)
	{
		is_critical = 0; /* DEFAULT FALSE */

		if (mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != MBEDTLS_SUCCESS_RET)
		{
			return false;
		}

		end_ext_data = *p + len;

		/* Get extension ID */
		if (mbedtls_asn1_get_tag(p, end_ext_data, &len, MBEDTLS_ASN1_OID) != MBEDTLS_SUCCESS_RET)
		{
			return false;
		}
		std::string oid(reinterpret_cast<char*>(*p), len);

		*p += len;

		/* Get optional critical */
		mbedRet = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical);
		if (mbedRet != MBEDTLS_SUCCESS_RET && mbedRet != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
		{
			return false;
		}

		/* Data should be octet string type */
		if (mbedtls_asn1_get_tag(p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING) != MBEDTLS_SUCCESS_RET)
		{
			return false;
		}

		std::string data(reinterpret_cast<char*>(*p), len);
		end_ext_octet = *p + len;

		if (end_ext_octet != end_ext_data)
		{
			return false;
		}

		if (extMap.find(oid) != extMap.end())
		{
			std::pair<bool, std::string>& destRef = extMap[oid];
			destRef.first = is_critical != 0;
			destRef.second.swap(data);
		}

		*p = end_ext_octet;
	}

	return true;
}

bool X509Cert::VerifySignature() const
{
	return *this && VerifySignature(ECKeyPublic(Get()->pk));
}

bool X509Cert::VerifySignature(const PKey & pubKey) const
{
	if (!*this || !pubKey)
	{
		return false;
	}

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(Get()->sig_md);
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	bool verifyRes =
		(mbedtls_md(mdInfo, Get()->tbs.p, Get()->tbs.len, hash) == MBEDTLS_SUCCESS_RET) &&
		(mbedtls_pk_verify_ext(Get()->sig_pk, Get()->sig_opts, pubKey.Get(),
			Get()->sig_md, hash, mbedtls_md_get_size(mdInfo),
			Get()->sig.p, Get()->sig.len) == MBEDTLS_SUCCESS_RET);

	return verifyRes;
}

bool X509Cert::Verify(const X509Cert & trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void * vrfyParam) const
{
	if (!*this)
	{
		return false;
	}
	uint32_t flag = 0;
	return mbedtls_x509_crt_verify(Get(), trustedCa.Get(), caCrl,
		commonName, &flag, vrfyFunc, vrfyParam) == MBEDTLS_SUCCESS_RET && flag == 0;
}

bool X509Cert::Verify(const X509Cert & trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, const mbedtls_x509_crt_profile & profile, int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void * vrfyParam) const
{
	if (!*this)
	{
		return false;
	}
	uint32_t flag = 0;
	return mbedtls_x509_crt_verify_with_profile(Get(), trustedCa.Get(), caCrl, 
		&profile, commonName, &flag, vrfyFunc, vrfyParam) == MBEDTLS_SUCCESS_RET && flag == 0;
}

const PKey & X509Cert::GetPublicKey() const
{
	return m_pubKey;
}

std::string X509Cert::GeneratePemStr(const mbedtls_x509_crt & ref)
{
	size_t useLen = CalcPemMaxBytes(ref.raw.len, sizeof(PEM_BEGIN_CRT) - 1, sizeof(PEM_END_CRT) - 1);

	std::string res(useLen, 0);
	if (mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT, ref.raw.p, ref.raw.len,
		reinterpret_cast<uint8_t*>(&res[0]), res.size(), &useLen) != MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	for (; res.back() == '\0'; res.pop_back());
	return res;
}

std::string X509Cert::ToPemString() const
{
	std::string res;
	int chainLen = 0;
	for (const mbedtls_x509_crt* it = Get(); it != nullptr; ++chainLen, it = it->next)
	{
		res += GeneratePemStr(*it);
	}
	LOGI("Generated X509 PEM Chain with length %d.", chainLen);

	return res;
}

std::string Decent::MbedTlsObj::X509Cert::GetCommonName() const
{
	if (!Get() || !(Get()->subject.val.p) || !(Get()->subject.val.len))
	{
		return std::string();
	}

	return std::string(reinterpret_cast<const char*>(Get()->subject.val.p), Get()->subject.val.len);
}

bool X509Cert::NextCert()
{
	if (Get() && Get()->next)
	{
		m_certStack.push_back(Get());
		SetPtr(Get()->next);
		m_pubKey = PKey(Get()->pk);
		return true;
	}
	return false;
}

bool X509Cert::PreviousCert()
{
	if (m_certStack.size() > 0)
	{
		SetPtr(m_certStack.back());
		m_pubKey = PKey(Get()->pk);
		m_certStack.pop_back();
		return true;
	}
	return false;
}

void X509Cert::SwitchToFirstCert()
{
	if (m_certStack.size() > 0)
	{
		SetPtr(m_certStack[0]);
		m_pubKey = PKey(Get()->pk);
		m_certStack.clear();
	}
}

X509Crl X509Crl::FromPemDer(const void* ptr, size_t size)
{
	X509Crl res;
	const uint8_t* ptrByte = static_cast<const uint8_t*>(ptr);

	if (mbedtls_x509_crl_parse(res.Get(), ptrByte, size) != MBEDTLS_SUCCESS_RET)
	{
		return X509Crl(nullptr, &ObjBase::DoNotFree);
	}

	return res;
}

X509Crl X509Crl::FromPem(const std::string & pemStr)
{
	return FromPemDer(pemStr.c_str(), pemStr.size() + 1);
}

void X509Crl::FreeObject(mbedtls_x509_crl * ptr)
{
	mbedtls_x509_crl_free(ptr);
	delete ptr;
}

std::string X509Crl::ToPemString() const
{
	size_t useLen = CalcPemMaxBytes(Get()->raw.len, sizeof(PEM_BEGIN_CRL) - 1, sizeof(PEM_END_CRL) - 1);

	std::string res(useLen, 0);
	if (mbedtls_pem_write_buffer(PEM_BEGIN_CRL, PEM_END_CRL, Get()->raw.p, Get()->raw.len,
		reinterpret_cast<uint8_t*>(&res[0]), res.size(), &useLen) != MBEDTLS_SUCCESS_RET)
	{
		return std::string();
	}

	res.pop_back();
	return res;
}

X509Crl::X509Crl() :
	ObjBase(new mbedtls_x509_crl, &FreeObject)
{
	mbedtls_x509_crl_init(Get());
}

void EntropyCtx::FreeObject(mbedtls_entropy_context * ptr)
{
	mbedtls_entropy_free(ptr);
	delete ptr;
}

EntropyCtx::EntropyCtx() :
	ObjBase(new mbedtls_entropy_context, &FreeObject),
	m_mbedTlsInit(MbedTlsHelper::MbedTlsInitializer::GetInst())
{
	mbedtls_entropy_init(Get());
}
