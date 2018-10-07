#include "MbedTlsObjects.h"

#include <memory>

#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../common/MbedTlsHelpers.h"

using namespace MbedTlsObj;

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

	static constexpr size_t ECP_PUB_DER_MAX_BYTES = (30 + 2 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t ECP_PRV_DER_MAX_BYTES = (29 + 3 * MBEDTLS_ECP_MAX_BYTES);
	static constexpr size_t X509_REQ_DER_MAX_BYTES = 4096; //From x509write_csr.c

	static constexpr size_t CalcPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
	{
		return headerSize + 
			cppcodec::base64_rfc4648::encoded_size(derMaxSize) + 
			(derMaxSize / 64) +  //'\n' for each line.
			footerSize + 
			1;                   //null terminator
	}

	static constexpr size_t ECP_PUB_PEM_MAX_BYTES = 
		CalcPemMaxBytes(ECP_PUB_DER_MAX_BYTES, sizeof(PEM_BEGIN_PUBLIC_KEY), sizeof(PEM_END_PUBLIC_KEY));

	static constexpr size_t ECP_PRV_PEM_MAX_BYTES =
		CalcPemMaxBytes(ECP_PRV_DER_MAX_BYTES, sizeof(PEM_BEGIN_PRIVATE_KEY_EC), sizeof(PEM_END_PRIVATE_KEY_EC));

	static constexpr size_t X509_REQ_PEM_MAX_BYTES =
		CalcPemMaxBytes(X509_REQ_DER_MAX_BYTES, sizeof(PEM_BEGIN_CSR), sizeof(PEM_END_CSR));


}

static mbedtls_pk_context* ConstructEcPubFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
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

ECKeyPublic::ECKeyPublic(mbedtls_pk_context * ptr, bool isOwner) :
	ObjBase(ptr),
	m_isOwner(isOwner)
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
	ObjBase(std::forward<ObjBase>(other)),
	m_isOwner(other.m_isOwner)
{
	other.m_isOwner = false;
}

ECKeyPublic::~ECKeyPublic()
{
	if (*this && m_isOwner)
	{
		mbedtls_pk_free(m_ptr);
		delete m_ptr;
	}
}

ECKeyPublic & ECKeyPublic::operator=(ECKeyPublic && other)
{
	if (this != &other)
	{
		ObjBase::operator=(std::forward<ObjBase>(other));
		this->m_isOwner = other.m_isOwner;
		other.m_isOwner = false;
	}
	return *this;
}

bool ECKeyPublic::ToGeneralPublicKey(general_secp256r1_public_t & outKey) const
{
	if (!*this)
	{
		return false;
	}

	const mbedtls_ecp_keypair* ecPtr = GetInternalECKey();

	if (mbedtls_mpi_write_binary(&ecPtr->Q.X, outKey.x, sizeof(outKey.x)) != MBEDTLS_SUCCESS_RET ||
		mbedtls_mpi_write_binary(&ecPtr->Q.Y, outKey.y, sizeof(outKey.y)) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}
	
	std::reverse(std::begin(outKey.x), std::end(outKey.x));
	std::reverse(std::begin(outKey.y), std::end(outKey.y));

	return true;
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
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
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

static mbedtls_pk_context* GenerateEcKeyPair()
{
	std::unique_ptr<mbedtls_pk_context> res(new mbedtls_pk_context);
	mbedtls_pk_init(res.get());
	mbedtls_ecp_keypair* ecPtr = nullptr;
	void* drbgCtx;
	MbedTlsHelper::MbedTlsHelperDrbgInit(drbgCtx);

	if (mbedtls_pk_setup(res.get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY))
		!= MBEDTLS_SUCCESS_RET ||
		!(ecPtr = mbedtls_pk_ec(*res)) ||
		mbedtls_ecp_gen_key(SECP256R1_CURVE_ID, ecPtr, &MbedTlsHelper::MbedTlsHelperDrbgRandom, drbgCtx)
		!= MBEDTLS_SUCCESS_RET)
	{
		MbedTlsHelper::MbedTlsHelperDrbgFree(drbgCtx);
		mbedtls_pk_free(res.get());
		return nullptr;
	}
	
	MbedTlsHelper::MbedTlsHelperDrbgFree(drbgCtx);
	return res.release();
}

ECKeyPair::ECKeyPair(mbedtls_pk_context * ptr, bool isOwner) :
	ECKeyPublic(ptr, isOwner)
{
}

ECKeyPair::ECKeyPair(GeneratePair) :
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

ECKeyPair::~ECKeyPair()
{
	//if (*this && m_isOwner)
	//{
	//	mbedtls_pk_free(m_ptr);
	//	delete m_ptr;
	//}
}

bool ECKeyPair::ToGeneralPrivateKey(general_secp256r1_private_t & outKey) const
{
	if (!*this)
	{
		return false;
	}

	const mbedtls_ecp_keypair* ecPtr = GetInternalECKey();

	if (mbedtls_mpi_write_binary(&ecPtr->d, outKey.r, sizeof(outKey.r)) != MBEDTLS_SUCCESS_RET)
	{
		return false;
	}

	std::reverse(std::begin(outKey.r), std::end(outKey.r));

	return true;
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
	std::unique_ptr<mbedtls_x509_csr> res(new mbedtls_x509_csr);
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

static const std::string CreateX509Pem(const ECKeyPair & keyPair, const std::string& commonName)
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
	MbedTlsHelper::MbedTlsHelperDrbgInit(drbgCtx);

	std::vector<char> tmpRes(X509_REQ_PEM_MAX_BYTES);
	int mbedRet = mbedtls_x509write_csr_pem(&csr, 
		reinterpret_cast<unsigned char*>(tmpRes.data()), tmpRes.size(), 
		&MbedTlsHelper::MbedTlsHelperDrbgRandom, drbgCtx);

	MbedTlsHelper::MbedTlsHelperDrbgFree(drbgCtx);

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

MbedTlsObj::X509Req::X509Req(const ECKeyPair & keyPair, const std::string& commonName) :
	X509Req(CreateX509Pem(keyPair, commonName))
{
}

MbedTlsObj::X509Req::~X509Req()
{
	if (!*this)
	{
		mbedtls_x509_csr_free(m_ptr);
		delete m_ptr;
	}
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

const ECKeyPublic & MbedTlsObj::X509Req::GetPublicKey() const
{
	return m_pubKey;
}

std::string MbedTlsObj::X509Req::ToPemString() const
{
	return m_pemStr;
}

static mbedtls_x509_crt* ConstructX509CertFromPemDer(const uint8_t* ptr, size_t size)
{
	std::unique_ptr<mbedtls_x509_crt> res(new mbedtls_x509_crt);
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

MbedTlsObj::X509Cert::X509Cert(const std::string & pemStr) :
	X509Cert(ConstructX509CertFromPem(pemStr), pemStr)
{
}

MbedTlsObj::X509Cert::X509Cert(mbedtls_x509_crt * ptr, const std::string & pemStr) :
	ObjBase(ptr),
	m_pemStr(pemStr),
	m_pubKey(ptr ? &ptr->pk : nullptr, false)
{
}

MbedTlsObj::X509Cert::~X509Cert()
{
	if (!*this)
	{
		mbedtls_x509_crt_free(m_ptr);
		delete m_ptr;
	}
}
