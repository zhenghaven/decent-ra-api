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
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pem.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/ssl.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "MbedTlsHelpers.h"
#include "../Common.h"
#include "../make_unique.h"

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
	static constexpr int MBEDTLS_SUCCESS_RET = 0;

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

	static constexpr size_t ECP_PUB_DER_MAX_BYTES = (30 + 2 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t ECP_PRV_DER_MAX_BYTES = (29 + 3 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t X509_REQ_DER_MAX_BYTES = 4096; //From x509write_csr.c
	static constexpr size_t X509_CRT_DER_MAX_BYTES = 4096; //From x509write_crt.c

	static constexpr size_t CalcPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
	{
		return headerSize + 
			cppcodec::base64_rfc4648::encoded_size(derMaxSize) + 
			(cppcodec::base64_rfc4648::encoded_size(derMaxSize) / 64) +  //'\n' for each line.
			footerSize + 
			1;                   //null terminator
	}

	static constexpr size_t ECP_PUB_PEM_MAX_BYTES = 
		CalcPemMaxBytes(ECP_PUB_DER_MAX_BYTES, sizeof(PEM_BEGIN_PUBLIC_KEY), sizeof(PEM_END_PUBLIC_KEY));

	static constexpr size_t ECP_PRV_PEM_MAX_BYTES =
		CalcPemMaxBytes(ECP_PRV_DER_MAX_BYTES, sizeof(PEM_BEGIN_PRIVATE_KEY_EC), sizeof(PEM_END_PRIVATE_KEY_EC));

	static constexpr size_t X509_REQ_PEM_MAX_BYTES =
		CalcPemMaxBytes(X509_REQ_DER_MAX_BYTES, sizeof(PEM_BEGIN_CSR), sizeof(PEM_END_CSR));

	static constexpr size_t X509_CRT_PEM_MAX_BYTES =
		CalcPemMaxBytes(X509_CRT_DER_MAX_BYTES, sizeof(PEM_BEGIN_CRT), sizeof(PEM_END_CRT));


}

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

BigNumber MbedTlsObj::BigNumber::GenRandomNumber(size_t size)
{
	std::unique_ptr<mbedtls_mpi> serialNum = Tools::make_unique<mbedtls_mpi>();
	mbedtls_mpi_init(serialNum.get());

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);

	int mbedRet = mbedtls_mpi_fill_random(serialNum.get(), size,
		&MbedTlsHelper::DrbgRandom, drbgCtx);

	MbedTlsHelper::DrbgFree(drbgCtx);

	if (mbedRet != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_mpi_free(serialNum.get());
		return BigNumber(nullptr);
	}

	return BigNumber(serialNum.release());
}

BigNumber MbedTlsObj::BigNumber::FromLittleEndianBin(const uint8_t * in, const size_t size)
{
	std::vector<uint8_t> tmpBuf(std::reverse_iterator<const uint8_t*>(in + size), std::reverse_iterator<const uint8_t*>(in));

	BigNumber res(MbedTlsObj::gen);
	if (!res ||
		mbedtls_mpi_read_binary(res.GetInternalPtr(), tmpBuf.data(), tmpBuf.size()) != MBEDTLS_SUCCESS_RET)
	{
		res.Destroy();
	}
	return res;
}

MbedTlsObj::BigNumber::BigNumber(const Generate &) :
	ObjBase(new mbedtls_mpi)
{
	mbedtls_mpi_init(m_ptr);
}

MbedTlsObj::BigNumber::BigNumber(BigNumber && other) :
	ObjBase(std::forward<ObjBase>(other))
{
}

MbedTlsObj::BigNumber::BigNumber(mbedtls_mpi * ptr) :
	ObjBase(ptr)
{
}

MbedTlsObj::BigNumber::~BigNumber()
{
	Destroy();
}

void MbedTlsObj::BigNumber::Destroy()
{
	if (m_ptr)
	{
		mbedtls_mpi_free(m_ptr);
		delete m_ptr;
	}
	m_ptr = nullptr;
}

bool MbedTlsObj::BigNumber::ToLittleEndianBinary(uint8_t * out, const size_t size)
{
	if (!*this || 
		mbedtls_mpi_size(m_ptr) != size ||
		mbedtls_mpi_write_binary(m_ptr, out, size) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}

	std::reverse(out, out + size);
	return true;
}

MbedTlsObj::PKey::PKey(mbedtls_pk_context * ptr, bool isOwner) :
	ObjBase(ptr),
	m_isOwner(isOwner)
{
}

MbedTlsObj::PKey::PKey(PKey && other) :
	ObjBase(std::forward<ObjBase>(other)),
	m_isOwner(other.m_isOwner)
{
	other.m_isOwner = false;
}

MbedTlsObj::PKey::~PKey()
{
	Destroy();
}

void MbedTlsObj::PKey::Destroy()
{
	if (m_ptr && m_isOwner)
	{
		mbedtls_pk_free(m_ptr);
		delete m_ptr;
	}
	m_isOwner = false;
	m_ptr = nullptr;
}

PKey & MbedTlsObj::PKey::operator=(PKey && other)
{
	if (this != &other)
	{
		ObjBase::operator=(std::forward<ObjBase>(other));
		this->m_isOwner = other.m_isOwner;
		other.m_isOwner = false;
	}
	return *this;
}

bool MbedTlsObj::PKey::VerifySignatureSha256(const General256Hash& hash, const std::vector<uint8_t>& signature) const
{
	if (!*this)
	{
		return false;
	}
	return mbedtls_pk_verify(m_ptr, mbedtls_md_type_t::MBEDTLS_MD_SHA256, hash.data(), hash.size(), signature.data(), signature.size()) == MBEDTLS_SUCCESS_RET;
}

MbedTlsObj::Gcm::Gcm(mbedtls_gcm_context * ptr) :
	ObjBase(ptr)
{
}

MbedTlsObj::Gcm::Gcm(Gcm && other) :
	ObjBase(std::forward<ObjBase>(other))
{
}

MbedTlsObj::Gcm::~Gcm()
{
	Destroy();
}

void MbedTlsObj::Gcm::Destroy()
{
	if (m_ptr)
	{
		mbedtls_gcm_free(m_ptr);
		delete m_ptr;
	}
	m_ptr = nullptr;
}

Gcm & MbedTlsObj::Gcm::operator=(Gcm && other)
{
	if (this != &other)
	{
		ObjBase::operator=(std::forward<ObjBase>(other));
	}
	return *this;
}

bool MbedTlsObj::Gcm::Encrypt(const uint8_t * inData, uint8_t * outData, const size_t dataLen, 
	const uint8_t* iv, const size_t ivLen, const uint8_t * add, const size_t addLen,
	uint8_t* tag, const size_t tagLen)
{
	if (!*this)
	{
		return false;
	}
	return mbedtls_gcm_crypt_and_tag(m_ptr, MBEDTLS_GCM_ENCRYPT, dataLen, 
		iv, ivLen, add, addLen, inData, outData, tagLen, tag) == MBEDTLS_SUCCESS_RET;
}

bool MbedTlsObj::Gcm::Decrypt(const uint8_t * inData, uint8_t * outData, const size_t dataLen, 
	const uint8_t * iv, const size_t ivLen, const uint8_t * add, const size_t addLen,
	const uint8_t* tag, const size_t tagLen)
{
	if (!*this)
	{
		return false;
	}
	return mbedtls_gcm_auth_decrypt(m_ptr, dataLen,
		iv, ivLen, add, addLen, tag, tagLen, inData, outData) == MBEDTLS_SUCCESS_RET;
}

static mbedtls_pk_context* ConstructEcPubFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_pk_context> res = Tools::make_unique<mbedtls_pk_context>();
	mbedtls_pk_init(res.get());

	if (mbedtls_pk_parse_public_key(res.get(), ptr, size)
		!= MBEDTLS_SUCCESS_RET ||
		mbedtls_pk_get_type(res.get()) != mbedtls_pk_type_t::MBEDTLS_PK_ECKEY)
	{
		mbedtls_pk_free(res.get());
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
	std::unique_ptr<mbedtls_pk_context> res = Tools::make_unique<mbedtls_pk_context>();
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

ECKeyPublic::ECKeyPublic(mbedtls_pk_context * ptr, bool isOwner) :
	PKey(ptr, isOwner)
{
}

ECKeyPublic::ECKeyPublic(const general_secp256r1_public_t & pub) :
	ECKeyPublic(ConstructEcPubFromGeneral(pub), true)
{
}

ECKeyPublic::ECKeyPublic(const std::string & pemStr) :
	ECKeyPublic(ConstructEcPubFromPem(pemStr), true)
{
}

ECKeyPublic::ECKeyPublic(ECKeyPublic && other) :
	PKey(std::forward<PKey>(other))
{
}

ECKeyPublic & ECKeyPublic::operator=(ECKeyPublic && other)
{
	if (this != &other)
	{
		PKey::operator=(std::forward<PKey>(other));
	}
	return *this;
}

MbedTlsObj::ECKeyPublic::operator bool() const
{
	return PKey::operator bool() &&
		mbedtls_pk_can_do(GetInternalPtr(), mbedtls_pk_type_t::MBEDTLS_PK_ECKEY);
}

bool MbedTlsObj::ECKeyPublic::ToGeneralPubKey(general_secp256r1_public_t & outKey) const
{
	if (!*this)
	{
		return false;
	}
	
	const mbedtls_ecp_keypair& ecPtr = *GetInternalECKey();
	
	if (mbedtls_mpi_write_binary(&ecPtr.Q.X, outKey.x, sizeof(outKey.x)) != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_write_binary(&ecPtr.Q.Y, outKey.y, sizeof(outKey.y)) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}
	
	std::reverse(std::begin(outKey.x), std::end(outKey.x));
	std::reverse(std::begin(outKey.y), std::end(outKey.y));
	
	return true;
}

std::unique_ptr<general_secp256r1_public_t> MbedTlsObj::ECKeyPublic::ToGeneralPubKey() const
{
	std::unique_ptr<general_secp256r1_public_t> pubKey = Tools::make_unique<general_secp256r1_public_t>();
	if (!pubKey || !ToGeneralPubKey(*pubKey))
	{
		return nullptr;
	}
	return std::move(pubKey);
}

general_secp256r1_public_t MbedTlsObj::ECKeyPublic::ToGeneralPubKeyChecked() const
{
	general_secp256r1_public_t pubKey;
	ToGeneralPubKey(pubKey);
	return pubKey;
}

bool MbedTlsObj::ECKeyPublic::VerifySign(const general_secp256r1_signature_t & inSign, const uint8_t * hash, const size_t hashLen) const
{
	if (!*this || !hash || hashLen <= 0)
	{
		return false;
	}
	BigNumber r(BigNumber::FromLittleEndianBin(inSign.x));
	BigNumber s(BigNumber::FromLittleEndianBin(inSign.y));
	EcGroupWarp grp;

	if (!r || !s || !grp.Copy(GetInternalECKey()->grp))
	{
		return false;
	}

	return mbedtls_ecdsa_verify(&grp.m_grp, hash, hashLen, &GetInternalECKey()->Q,
		r.GetInternalPtr(), s.GetInternalPtr()) == MBEDTLS_SUCCESS_RET;
}

std::string ECKeyPublic::ToPubPemString() const
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

bool ECKeyPublic::ToPubDerArray(std::vector<uint8_t>& outArray) const
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

mbedtls_ecp_keypair * ECKeyPublic::GetInternalECKey() const
{
	if (!*this)
	{
		return nullptr;
	}
	return mbedtls_pk_ec(*m_ptr);
}

static mbedtls_pk_context* ConstructEcPrvFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_pk_context> res = Tools::make_unique<mbedtls_pk_context>();
	mbedtls_pk_init(res.get());

	if (mbedtls_pk_parse_key(res.get(), ptr, size, nullptr, 0)
		!= MBEDTLS_SUCCESS_RET ||
		mbedtls_pk_get_type(res.get()) != mbedtls_pk_type_t::MBEDTLS_PK_ECKEY)
	{
		mbedtls_pk_free(res.get());
		return nullptr;
	}

	return res.release();
}

static mbedtls_pk_context* ConstructEcPrvFromPem(const std::string & pemStr)
{
	return ConstructEcPrvFromPemDer(reinterpret_cast<const uint8_t*>(pemStr.c_str()), pemStr.size() + 1);
}

static bool CheckPublicAndPrivatePair(const mbedtls_ecp_keypair* pair)
{
	mbedtls_ecp_point Q;
	mbedtls_ecp_group grp;

	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_group_init(&grp);

	mbedtls_ecp_group_copy(&grp, &pair->grp);

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);
	int mbedRet = mbedtls_ecp_mul(&grp, &Q, &pair->d, &grp.G, &MbedTlsHelper::DrbgRandom, drbgCtx);
	MbedTlsHelper::DrbgFree(drbgCtx);

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
	std::unique_ptr<mbedtls_pk_context> res = Tools::make_unique<mbedtls_pk_context>();
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
		MbedTlsHelper::DrbgInit(drbgCtx);
		int mbedRet = mbedtls_ecp_mul(&ecPtr->grp, &ecPtr->Q, &ecPtr->d, &ecPtr->grp.G, &MbedTlsHelper::DrbgRandom, drbgCtx);
		MbedTlsHelper::DrbgFree(drbgCtx);
		if (mbedRet != MBEDTLS_SUCCESS_RET)
		{
			mbedtls_pk_free(res.get());
			return nullptr;
		}
	}

	return res.release();
}

static mbedtls_pk_context* GenerateEcKeyPair()
{
	std::unique_ptr<mbedtls_pk_context> res = Tools::make_unique<mbedtls_pk_context>();
	mbedtls_pk_init(res.get());
	mbedtls_ecp_keypair* ecPtr = nullptr;
	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);

	if (mbedtls_pk_setup(res.get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY))
		!= MBEDTLS_SUCCESS_RET ||
		!(ecPtr = mbedtls_pk_ec(*res)) ||
		mbedtls_ecp_gen_key(SECP256R1_CURVE_ID, ecPtr, &MbedTlsHelper::DrbgRandom, drbgCtx)
		!= MBEDTLS_SUCCESS_RET)
	{
		MbedTlsHelper::DrbgFree(drbgCtx);
		mbedtls_pk_free(res.get());
		return nullptr;
	}
	
	MbedTlsHelper::DrbgFree(drbgCtx);
	return res.release();
}

ECKeyPair::ECKeyPair(mbedtls_pk_context * ptr, bool isOwner) :
	ECKeyPublic(ptr, isOwner)
{
}

ECKeyPair::ECKeyPair(const Generate&) :
	ECKeyPair(GenerateEcKeyPair(), true)
{
}

ECKeyPair::ECKeyPair(const general_secp256r1_private_t & prv) :
	ECKeyPair(ConstructEcPrvFromGeneral(prv, nullptr), true)
{
}

ECKeyPair::ECKeyPair(const general_secp256r1_private_t & prv, const general_secp256r1_public_t & pub) :
	ECKeyPair(ConstructEcPrvFromGeneral(prv, &pub), true)
{
}

ECKeyPair::ECKeyPair(const std::string & pemStr) :
	ECKeyPair(ConstructEcPrvFromPem(pemStr), true)
{
}

MbedTlsObj::ECKeyPair::ECKeyPair(ECKeyPair && other) :
	ECKeyPublic(std::forward<ECKeyPublic>(other))
{
}

bool MbedTlsObj::ECKeyPair::ToGeneralPrvKey(PrivateKeyWrap & outKey) const
{
	if (!*this)
	{
		return false;
	}

	const mbedtls_ecp_keypair& ecPtr = *GetInternalECKey();
	if (mbedtls_mpi_write_binary(&ecPtr.d, outKey.m_prvKey.r, sizeof(outKey.m_prvKey.r)) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}
	std::reverse(std::begin(outKey.m_prvKey.r), std::end(outKey.m_prvKey.r));

	return true;
}

std::unique_ptr<PrivateKeyWrap> MbedTlsObj::ECKeyPair::ToGeneralPrvKey() const
{
	std::unique_ptr<PrivateKeyWrap> prvKey = Tools::make_unique<PrivateKeyWrap>();
	if (!prvKey || !ToGeneralPrvKey(*prvKey))
	{
		return nullptr;
	}
	return std::move(prvKey);
}

PrivateKeyWrap MbedTlsObj::ECKeyPair::ToGeneralPrvKeyChecked() const
{
	PrivateKeyWrap prvKey;
	if (ToGeneralPrvKey(prvKey))
	{
		return prvKey;
	}

	return PrivateKeyWrap();
}

bool MbedTlsObj::ECKeyPair::GenerateSharedKey(General256BitKey & outKey, const ECKeyPublic & peerPubKey)
{
	if (!*this || !peerPubKey)
	{
		return false;
	}

	BigNumber sharedKey(MbedTlsObj::gen);
	EcGroupWarp grp;
	if (!sharedKey || !grp.Copy(GetInternalECKey()->grp))
	{
		return false;
	}

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);

	int mbedRet = mbedtls_ecdh_compute_shared(&grp.m_grp, sharedKey.GetInternalPtr(),
		&peerPubKey.GetInternalECKey()->Q, &GetInternalECKey()->d,
		&MbedTlsHelper::DrbgRandom, drbgCtx);

	MbedTlsHelper::DrbgFree(drbgCtx);

	if (mbedRet != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_size(sharedKey.GetInternalPtr()) != outKey.size() ||
		mbedtls_mpi_write_binary(sharedKey.GetInternalPtr(), outKey.data(), outKey.size()) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}

	std::reverse(outKey.begin(), outKey.end());

	return true;
}

bool MbedTlsObj::ECKeyPair::EcdsaSign(general_secp256r1_signature_t & outSign, const uint8_t * hash, const size_t hashLen, const mbedtls_md_info_t* mdInfo) const
{
	if (!*this || !hash || !mdInfo || hashLen != mdInfo->size)
	{
		return false;
	}

	int mbedRet = 0;
	BigNumber r(MbedTlsObj::gen);
	BigNumber s(MbedTlsObj::gen);
	EcGroupWarp grp;

	if (!r ||!s || !grp.Copy(GetInternalECKey()->grp))
	{
		return false;
	}

#ifdef MBEDTLS_ECDSA_DETERMINISTIC
	mbedRet = mbedtls_ecdsa_sign_det(&grp.m_grp, r.GetInternalPtr(), s.GetInternalPtr(), 
		&GetInternalECKey()->d, hash, hashLen, mdInfo->type);
#else
	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);
	mbedRet = mbedtls_ecdsa_sign(&grp.m_grp, r.GetInternalPtr(), s.GetInternalPtr(),
		&GetInternalECKey()->d, hash, hashLen, &MbedTlsHelper::DrbgRandom, drbgCtx);
	MbedTlsHelper::DrbgFree(drbgCtx);
#endif 

	return mbedRet == MBEDTLS_SUCCESS_RET && r.ToLittleEndianBinary(outSign.x) && s.ToLittleEndianBinary(outSign.y);
}

std::string ECKeyPair::ToPrvPemString() const
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

bool ECKeyPair::ToPrvDerArray(std::vector<uint8_t>& outArray) const
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

static mbedtls_x509_csr* ConstructX509ReqFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_x509_csr> res = Tools::make_unique<mbedtls_x509_csr>();
	mbedtls_x509_csr_init(res.get());

	if(mbedtls_x509_csr_parse(res.get(), ptr, size) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509_csr_free(res.get());
		return nullptr;
	}

	return res.release();
}

static mbedtls_x509_csr* ConstructX509ReqFromPem(const std::string & pemStr)
{
	return ConstructX509ReqFromPemDer(reinterpret_cast<const uint8_t*>(pemStr.c_str()), pemStr.size() + 1);
}

static const std::string CreateX509Pem(const PKey & keyPair, const std::string& commonName)
{
	if (!keyPair)
	{
		return std::string();
	}

	mbedtls_x509write_csr csr;
	mbedtls_x509write_csr_init(&csr);

	mbedtls_x509write_csr_set_key(&csr, keyPair.GetInternalPtr());
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
	if (mbedtls_x509write_csr_set_subject_name(&csr, ("CN=" + commonName).c_str()) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509write_csr_free(&csr);
		return std::string();
	}

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);

	std::vector<char> tmpRes(X509_REQ_PEM_MAX_BYTES);
	int mbedRet = mbedtls_x509write_csr_pem(&csr, 
		reinterpret_cast<unsigned char*>(tmpRes.data()), tmpRes.size(), 
		&MbedTlsHelper::DrbgRandom, drbgCtx);

	MbedTlsHelper::DrbgFree(drbgCtx);

	mbedtls_x509write_csr_free(&csr);
	return mbedRet == MBEDTLS_SUCCESS_RET ? std::string(tmpRes.data()) : std::string();
}

X509Req::X509Req(const std::string & pemStr) :
	X509Req(ConstructX509ReqFromPem(pemStr), pemStr)
{
}

MbedTlsObj::X509Req::X509Req(mbedtls_x509_csr * ptr, const std::string& pemStr) :
	ObjBase(ptr),
	m_pemStr(pemStr),
	m_pubKey(ptr ? &ptr->pk : nullptr, false)
{
}

MbedTlsObj::X509Req::X509Req(const PKey & keyPair, const std::string& commonName) :
	X509Req(CreateX509Pem(keyPair, commonName))
{
}

MbedTlsObj::X509Req::~X509Req()
{
	Destroy();
}

void MbedTlsObj::X509Req::Destroy()
{
	m_pubKey.Destroy();
	if (m_ptr)
	{
		mbedtls_x509_csr_free(m_ptr);
		delete m_ptr;
	}
	m_ptr = nullptr;
}

MbedTlsObj::X509Req& MbedTlsObj::X509Req::operator=(X509Req&& other)
{
	if (this != &other)
	{
		ObjBase::operator=(std::forward<ObjBase>(other));
		m_pemStr = std::move(other.m_pemStr);
		m_pubKey = std::move(other.m_pubKey);
	}
	return *this;
}

MbedTlsObj::X509Req::operator bool() const
{
	return ObjBase::operator bool() && m_pubKey;
}

bool MbedTlsObj::X509Req::VerifySignature() const
{
	if (!*this)
	{
		return false;
	}

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(m_ptr->sig_md);
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	bool verifyRes = 
		(mbedtls_md(mdInfo, m_ptr->cri.p, m_ptr->cri.len, hash) == MBEDTLS_SUCCESS_RET) &&
		(mbedtls_pk_verify_ext(m_ptr->sig_pk, m_ptr->sig_opts, &m_ptr->pk,
			m_ptr->sig_md, hash, mbedtls_md_get_size(mdInfo),
			m_ptr->sig.p, m_ptr->sig.len) == MBEDTLS_SUCCESS_RET);

	return verifyRes;
}

const PKey & MbedTlsObj::X509Req::GetPublicKey() const
{
	return m_pubKey;
}

std::string MbedTlsObj::X509Req::ToPemString() const
{
	return m_pemStr;
}

static mbedtls_x509_crt* ConstructX509CertFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_x509_crt> res = Tools::make_unique<mbedtls_x509_crt>();
	mbedtls_x509_crt_init(res.get());

	if (mbedtls_x509_crt_parse(res.get(), ptr, size) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509_crt_free(res.get());
		return nullptr;
	}

	return res.release();
}

static mbedtls_x509_crt* ConstructX509CertFromPem(const std::string & pemStr)
{
	return ConstructX509CertFromPemDer(reinterpret_cast<const uint8_t*>(pemStr.c_str()), pemStr.size() + 1);
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
	mbedtls_x509write_crt_set_issuer_key(&cert, prvKey.GetInternalPtr());
	mbedtls_x509write_crt_set_subject_key(&cert, pubKey.GetInternalPtr());

	time_t timerBegin;
	Tools::GetSystemTime(timerBegin);
	time_t timerEnd = timerBegin + validTime;

	if (mbedtls_x509write_crt_set_validity(&cert, GetFormatedTime(timerBegin).c_str(), GetFormatedTime(timerEnd).c_str()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_serial(&cert, serialNum.GetInternalPtr()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_subject_name(&cert, x509NameList.c_str()) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_basic_constraints(&cert, isCa, maxChainDepth) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_key_usage(&cert, keyUsage) != MBEDTLS_SUCCESS_RET ||
		mbedtls_x509write_crt_set_ns_cert_type(&cert, nsType) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509write_crt_free(&cert);
		return std::string();
	}

	size_t extTotalSize = 0;

	int mbedRet = hasCa ? MbedTlsHelper::MbedTlsAsn1DeepCopy(cert.issuer, caCert->GetInternalPtr()->issuer) :
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

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);

	std::vector<uint8_t> tmpDerBuf(X509_CRT_DER_MAX_BYTES + extTotalSize + 5);

	mbedRet = myX509WriteCrtDer(&cert, tmpDerBuf,
		&MbedTlsHelper::DrbgRandom, drbgCtx);

	MbedTlsHelper::DrbgFree(drbgCtx);
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

static std::string ConstructCommonName(mbedtls_x509_crt * ptr)
{
	if (!ptr || !(ptr->subject.val.p) || !(ptr->subject.val.len))
	{
		return std::string();
	}

	return std::string(reinterpret_cast<const char*>(ptr->subject.val.p), ptr->subject.val.len);
}

MbedTlsObj::X509Cert::X509Cert(const std::string & pemStr) :
	X509Cert(ConstructX509CertFromPem(pemStr), pemStr)
{
}

MbedTlsObj::X509Cert::X509Cert(mbedtls_x509_crt * ptr, const std::string & pemStr) :
	ObjBase(ptr),
	m_isOwner(true),
	m_pemStr(pemStr),
	m_pubKey(ptr ? &ptr->pk : nullptr, false),
	m_commonName(ConstructCommonName(ptr))
{
}

MbedTlsObj::X509Cert::X509Cert(mbedtls_x509_crt * ptr) :
	X509Cert(ptr, std::string())
{
}

MbedTlsObj::X509Cert::X509Cert(const X509Cert & caCert, const PKey & prvKey, const PKey & pubKey,
	const BigNumber & serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
	const std::string & x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap) :
	X509Cert(ConstructNewX509Cert(&caCert, prvKey, pubKey, 
		serialNum, validTime, isCa, maxChainDepth, keyUsage, nsType,
		x509NameList, extMap))
{
}

MbedTlsObj::X509Cert::X509Cert(const PKey & prvKey,
	const BigNumber & serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
	const std::string & x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap) :
	X509Cert(ConstructNewX509Cert(nullptr, prvKey, prvKey, 
		serialNum, validTime, isCa, maxChainDepth, keyUsage, nsType,
		x509NameList, extMap))
{
}

MbedTlsObj::X509Cert::~X509Cert()
{
	Destroy();
}

void MbedTlsObj::X509Cert::Destroy()
{
	m_pubKey.Destroy();

	SwitchToFirstCert();
	if (m_isOwner && m_ptr)
	{
		mbedtls_x509_crt_free(m_ptr);
		delete m_ptr;
	}
	m_ptr = nullptr;
}

MbedTlsObj::X509Cert& MbedTlsObj::X509Cert::operator=(X509Cert&& other)
{
	if (this != &other)
	{
		ObjBase::operator=(std::forward<ObjBase>(other));
		m_isOwner = other.m_isOwner;
		m_pemStr = std::move(other.m_pemStr);
		m_pubKey = std::move(other.m_pubKey);
		m_certStack = std::move(other.m_certStack);
		other.m_isOwner = false;
	}
	return *this;
}

MbedTlsObj::X509Cert::operator bool() const
{
	return ObjBase::operator bool() && m_pubKey && m_commonName.size() > 0;
}

bool MbedTlsObj::X509Cert::GetExtensions(std::map<std::string, std::pair<bool, std::string> >& extMap) const
{
	if (!MbedTlsObj::X509Cert::operator bool())
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

	unsigned char *begin = m_ptr->v3_ext.p;
	const unsigned char *end = m_ptr->v3_ext.p + m_ptr->v3_ext.len;

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

bool MbedTlsObj::X509Cert::VerifySignature() const
{
	return *this && VerifySignature(ECKeyPublic(&m_ptr->pk, false));
}

bool MbedTlsObj::X509Cert::VerifySignature(const PKey & pubKey) const
{
	if (!*this || !pubKey)
	{
		return false;
	}

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(m_ptr->sig_md);
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	bool verifyRes =
		(mbedtls_md(mdInfo, m_ptr->tbs.p, m_ptr->tbs.len, hash) == MBEDTLS_SUCCESS_RET) &&
		(mbedtls_pk_verify_ext(m_ptr->sig_pk, m_ptr->sig_opts, pubKey.GetInternalPtr(),
			m_ptr->sig_md, hash, mbedtls_md_get_size(mdInfo),
			m_ptr->sig.p, m_ptr->sig.len) == MBEDTLS_SUCCESS_RET);

	return verifyRes;
}

bool MbedTlsObj::X509Cert::Verify(const X509Cert & trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void * vrfyParam) const
{
	if (!*this)
	{
		return false;
	}
	uint32_t flag = 0;
	return mbedtls_x509_crt_verify(m_ptr, trustedCa.GetInternalPtr(), caCrl,
		commonName, &flag, vrfyFunc, vrfyParam) == MBEDTLS_SUCCESS_RET && flag == 0;
}

bool MbedTlsObj::X509Cert::Verify(const X509Cert & trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, const mbedtls_x509_crt_profile & profile, int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void * vrfyParam) const
{
	if (!*this)
	{
		return false;
	}
	uint32_t flag = 0;
	return mbedtls_x509_crt_verify_with_profile(m_ptr, trustedCa.GetInternalPtr(), caCrl, 
		&profile, commonName, &flag, vrfyFunc, vrfyParam) == MBEDTLS_SUCCESS_RET && flag == 0;
}

const PKey & MbedTlsObj::X509Cert::GetPublicKey() const
{
	return m_pubKey;
}

const std::string & MbedTlsObj::X509Cert::ToPemString() const
{
	return m_pemStr;
}

bool MbedTlsObj::X509Cert::NextCert()
{
	if (m_ptr && m_ptr->next)
	{
		m_certStack.push_back(m_ptr);
		m_ptr = m_ptr->next;
		m_pubKey = PKey(&m_ptr->pk, false);
		return true;
	}
	return false;
}

bool MbedTlsObj::X509Cert::PreviousCert()
{
	if (m_certStack.size() > 0)
	{
		m_ptr = m_certStack.back();
		m_pubKey = PKey(&m_ptr->pk, false);
		m_certStack.pop_back();
		return true;
	}
	return false;
}

void MbedTlsObj::X509Cert::SwitchToFirstCert()
{
	if (m_certStack.size() > 0)
	{
		m_ptr = m_certStack[0];
		m_pubKey = PKey(&m_ptr->pk, false);
		m_certStack.clear();
	}
}

static mbedtls_x509_crl* ConstructX509CrlFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_x509_crl> res = Tools::make_unique<mbedtls_x509_crl>();
	mbedtls_x509_crl_init(res.get());

	if (mbedtls_x509_crl_parse(res.get(), ptr, size) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_x509_crl_free(res.get());
		return nullptr;
	}

	return res.release();
}

static mbedtls_x509_crl* ConstructX509CrlFromPem(const std::string & pemStr)
{
	return ConstructX509CrlFromPemDer(reinterpret_cast<const uint8_t*>(pemStr.c_str()), pemStr.size() + 1);
}

MbedTlsObj::X509Crl::X509Crl(const std::string & pemStr) :
	X509Crl(ConstructX509CrlFromPem(pemStr), pemStr)
{
}

MbedTlsObj::X509Crl::X509Crl(mbedtls_x509_crl * ptr, const std::string & pemStr) :
	ObjBase(ptr),
	m_pemStr(pemStr)
{
}

MbedTlsObj::X509Crl::~X509Crl()
{
	Destroy();
}

void MbedTlsObj::X509Crl::Destroy()
{
	if (m_ptr)
	{
		mbedtls_x509_crl_free(m_ptr);
		delete m_ptr;
	}
	m_ptr = nullptr;
}

std::string MbedTlsObj::X509Crl::ToPemString() const
{
	return m_pemStr;
}

static mbedtls_gcm_context* ConstructGcmCtx(const uint8_t* key, const size_t size, mbedtls_cipher_id_t type)
{
	std::unique_ptr<mbedtls_gcm_context> res = Tools::make_unique<mbedtls_gcm_context>();
	mbedtls_gcm_init(res.get());

	if (mbedtls_gcm_setkey(res.get(), type, key, static_cast<unsigned int>(size * GENERAL_BITS_PER_BYTE)) != MBEDTLS_SUCCESS_RET)
	{
		mbedtls_gcm_free(res.get());
		return nullptr;
	}

	return res.release();
}

MbedTlsObj::Aes128Gcm::Aes128Gcm(const General128BitKey & key) :
	Gcm(ConstructGcmCtx(key.data(), key.size(), mbedtls_cipher_id_t::MBEDTLS_CIPHER_ID_AES))
{
}

MbedTlsObj::Aes128Gcm::Aes128Gcm(const uint8_t(&key)[GENERAL_128BIT_16BYTE_SIZE]) :
	Gcm(ConstructGcmCtx(key, GENERAL_128BIT_16BYTE_SIZE, mbedtls_cipher_id_t::MBEDTLS_CIPHER_ID_AES))
{
}

MbedTlsObj::Aes128Gcm::Aes128Gcm(Aes128Gcm && other) :
	Gcm(std::forward<Gcm>(other))
{
}

Aes128Gcm & MbedTlsObj::Aes128Gcm::operator=(Aes128Gcm && other)
{
	if (this != &other)
	{
		Gcm::operator=(std::forward<Gcm>(other));
	}
	return *this;
}

TlsConfig::TlsConfig(mbedtls_ssl_config * ptr) :
	ObjBase(ptr)
{
}

MbedTlsObj::TlsConfig::TlsConfig(TlsConfig && other) :
	ObjBase(std::forward<ObjBase>(other)),
	m_rng(other.m_rng)
{
	other.m_rng = nullptr;
}

MbedTlsObj::TlsConfig::~TlsConfig()
{
	Destroy();
}

void MbedTlsObj::TlsConfig::Destroy()
{
	if (m_ptr)
	{
		mbedtls_ssl_config_free(m_ptr);
		delete m_ptr;
	}
	if (m_rng)
	{
		MbedTlsHelper::DrbgFree(m_rng);
	}
	m_ptr = nullptr;
}

TlsConfig & MbedTlsObj::TlsConfig::operator=(TlsConfig && other)
{
	if (this != &other)
	{
		ObjBase::operator=(std::forward<ObjBase>(other));
		m_rng = other.m_rng;
		other.m_rng = nullptr;
	}
	return *this;
}

void MbedTlsObj::TlsConfig::BasicInit()
{
	if (!m_ptr)
	{
		return;
	}

	mbedtls_ssl_config_init(m_ptr);
	MbedTlsHelper::DrbgInit(m_rng);
	mbedtls_ssl_conf_rng(m_ptr, &MbedTlsHelper::DrbgRandom, m_rng);
}
