#include "X509Cert.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/pem.h>
#include <mbedtls/oid.h>

#include "RbgBase.h"
#include "BigNumber.h"
#include "AsymKeyBase.h"
#include "Internal/Pem.h"
#include "Internal/Hasher.h"
#include "Internal/make_unique.h"
#include "Internal/Asn1Helpers.h"
#include "Internal/Asn1SizeEstimators.h"

using namespace Decent::MbedTlsObj;

namespace
{
	static constexpr char const PEM_BEGIN_CRT[] = "-----BEGIN CERTIFICATE-----\n";
	static constexpr char const PEM_END_CRT[] = "-----END CERTIFICATE-----\n";

	static constexpr size_t PEM_CRT_HEADER_SIZE = sizeof(PEM_BEGIN_CRT) - 1;
	static constexpr size_t PEM_CRT_FOOTER_SIZE = sizeof(PEM_END_CRT) - 1;

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

	// This is copied from the future release of the mbedTLS in order to solve the issue caused by the fixed tmp_buf size. 
	// This duplicated function should be removed once it is released.
	static int mbedtls_x509write_crt_der_new_ver(mbedtls_x509write_cert *ctx,
		unsigned char *buf, size_t size,
		int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
	{
		int ret;
		const char *sig_oid;
		size_t sig_oid_len = 0;
		unsigned char *c, *c2;
		unsigned char hash[64];
		size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
		size_t len = 0;
		mbedtls_pk_type_t pk_alg;

		/*
		 * Prepare data to be signed at the end of the target buffer
		 */
		c = buf + size;

		/* Signature algorithm needed in TBS, and later for actual signature */

		/* There's no direct way of extracting a signature algorithm
		 * (represented as an element of mbedtls_pk_type_t) from a PK instance. */
		if (mbedtls_pk_can_do(ctx->issuer_key, MBEDTLS_PK_RSA))
			pk_alg = MBEDTLS_PK_RSA;
		else if (mbedtls_pk_can_do(ctx->issuer_key, MBEDTLS_PK_ECDSA))
			pk_alg = MBEDTLS_PK_ECDSA;
		else
			return(MBEDTLS_ERR_X509_INVALID_ALG);

		if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg, &sig_oid, &sig_oid_len)) != 0)
		{
			return(ret);
		}

		/*
		 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
		 */

		 /* Only for v3 */
		if (ctx->version == MBEDTLS_X509_CRT_VERSION_3)
		{
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_extensions(&c, buf, ctx->extensions));
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
					MBEDTLS_ASN1_CONSTRUCTED | 3));
		}

		/*
		 *  SubjectPublicKeyInfo
		 */
		MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_pk_write_pubkey_der(ctx->subject_key, buf, c - buf));
		c -= pub_len;
		len += pub_len;

		/*
		 *  Subject  ::=  Name
		 */
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf, ctx->subject));

		/*
		 *  Validity ::= SEQUENCE {
		 *       notBefore      Time,
		 *       notAfter       Time }
		 */
		sub_len = 0;

		MBEDTLS_ASN1_CHK_ADD(sub_len, x509_write_time(&c, buf, ctx->not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

		MBEDTLS_ASN1_CHK_ADD(sub_len, x509_write_time(&c, buf, ctx->not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

		len += sub_len;
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
				MBEDTLS_ASN1_SEQUENCE));

		/*
		 *  Issuer  ::=  Name
		 */
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_x509_write_names(&c, buf, ctx->issuer));

		/*
		 *  Signature   ::=  AlgorithmIdentifier
		 */
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&c, buf,
				sig_oid, strlen(sig_oid), 0));

		/*
		 *  Serial   ::=  INTEGER
		 */
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &ctx->serial));

		/*
		 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
		 */

		 /* Can be omitted for v1 */
		if (ctx->version != MBEDTLS_X509_CRT_VERSION_1)
		{
			sub_len = 0;
			MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_int(&c, buf, ctx->version));
			len += sub_len;
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
			MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC |
					MBEDTLS_ASN1_CONSTRUCTED | 0));
		}

		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
				MBEDTLS_ASN1_SEQUENCE));

		/*
		 * Make signature
		 */

		 /* Compute hash of CRT. */
		if ((ret = mbedtls_md(mbedtls_md_info_from_type(ctx->md_alg), c, len, hash)) != 0)
		{
			return(ret);
		}

		const size_t sigMaxLen = AsymKeyBase::EstimateDerSignatureSize(*ctx->issuer_key,
			mbedtls_md_get_size(mbedtls_md_info_from_type(ctx->md_alg)));
		std::unique_ptr<unsigned char[]> sig = detail::make_unique<unsigned char[]>(sigMaxLen);

		if ((ret = mbedtls_pk_sign(ctx->issuer_key, ctx->md_alg, hash, 0, sig.get(), &sig_len,
			f_rng, p_rng)) != 0)
		{
			return(ret);
		}

		/* Move CRT to the front of the buffer to have space
		 * for the signature. */
		memmove(buf, c, len);
		c = buf + len;

		/* Add signature at the end of the buffer,
		 * making sure that it doesn't underflow
		 * into the CRT buffer. */
		c2 = buf + size;
		MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, c, sig_oid, sig_oid_len, sig.get(), sig_len));

		/*
		 * Memory layout after this step:
		 *
		 * buf       c=buf+len                c2            buf+size
		 * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
		 */

		 /* Move raw CRT to just before the signature. */
		c = c2 - len;
		memmove(c, buf, len);

		len += sig_and_oid_len;
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
			MBEDTLS_ASN1_SEQUENCE));

		return((int)len);
	}

	static std::string GetPemByRef(const mbedtls_x509_crt& ref)
	{
		size_t pemLen = detail::CalcPemMaxBytes(ref.raw.len, PEM_CRT_HEADER_SIZE, PEM_CRT_FOOTER_SIZE);
		std::string pem(pemLen, '\0');

		size_t olen = 0;

		CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, PEM_BEGIN_CRT, PEM_END_CRT,
			ref.raw.p, ref.raw.len,
			reinterpret_cast<uint8_t*>(&pem[0]), pem.size(),
			&olen);

		pem.resize(olen);

		for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

		return pem;
	}
}

void X509CertWriter::FreeObject(mbedtls_x509write_cert * ptr)
{
	mbedtls_x509write_crt_free(ptr);
	delete ptr;
}

size_t X509CertWriter::EstimateX509CertDerSize(mbedtls_x509write_cert & ctx)
{
	using namespace detail;

	const char *sig_oid;
	size_t sig_oid_len = 0;
	size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len = 0;
	size_t len = 0;
	mbedtls_pk_type_t pk_alg;

	/* Signature algorithm needed in TBS, and later for actual signature */

	/* There's no direct way of extracting a signature algorithm
	 * (represented as an element of mbedtls_pk_type_t) from a PK instance. */
	if (mbedtls_pk_can_do(ctx.issuer_key, MBEDTLS_PK_RSA))
		pk_alg = MBEDTLS_PK_RSA;
	else if (mbedtls_pk_can_do(ctx.issuer_key, MBEDTLS_PK_ECDSA))
		pk_alg = MBEDTLS_PK_ECDSA;
	else
		throw MbedTlsException("EstimateX509ReqSize", MBEDTLS_ERR_X509_INVALID_ALG);

	CALL_MBEDTLS_C_FUNC(mbedtls_oid_get_oid_by_sig_alg, pk_alg, ctx.md_alg, &sig_oid, &sig_oid_len);

	/*
	 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	 */

	 /* Only for v3 */
	if (ctx.version == MBEDTLS_X509_CRT_VERSION_3)
	{
		len += mbedtls_x509_write_extensions_est_size(ctx.extensions);
		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3);
	}

	/*
	 *  SubjectPublicKeyInfo
	 */
	pub_len = AsymKeyBase::EstimatePublicKeyDerSize(*ctx.subject_key);
	len += pub_len;

	/*
	 *  Subject  ::=  Name
	 */
	len += mbedtls_x509_write_names_est_size(ctx.subject);

	/*
	 *  Validity ::= SEQUENCE {
	 *       notBefore      Time,
	 *       notAfter       Time }
	 */
	sub_len = 0;

	sub_len += x509_write_time_est_size(ctx.not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);

	sub_len += x509_write_time_est_size(ctx.not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);

	len += sub_len;
	len += mbedtls_asn1_write_len_est_size(sub_len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	/*
	 *  Issuer  ::=  Name
	 */
	len += mbedtls_x509_write_names_est_size(ctx.issuer);

	/*
	 *  Signature   ::=  AlgorithmIdentifier
	 */
	len += mbedtls_asn1_write_algorithm_identifier_est_size(sig_oid, strlen(sig_oid), 0);

	/*
	 *  Serial   ::=  INTEGER
	 */
	len += mbedtls_asn1_write_mpi_est_size(ctx.serial);

	/*
	 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */

	 /* Can be omitted for v1 */
	if (ctx.version != MBEDTLS_X509_CRT_VERSION_1)
	{
		sub_len = 0;
		sub_len += mbedtls_asn1_write_int_est_size(ctx.version);
		len += sub_len;
		len += mbedtls_asn1_write_len_est_size(sub_len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0);
	}

	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	/*
	 * Make signature
	 */

	 /* Compute hash of CRT. */

	sig_len = AsymKeyBase::EstimateDerSignatureSize(*ctx.issuer_key, mbedtls_md_get_size(mbedtls_md_info_from_type(ctx.md_alg)));


	/* Add signature at the end of the buffer,
	 * making sure that it doesn't underflow
	 * into the CRT buffer. */
	sig_and_oid_len += mbedtls_x509_write_sig_est_size(sig_oid, sig_oid_len, sig_len);

	/*
	 * Memory layout after this step:
	 *
	 * buf       c=buf+len                c2            buf+size
	 * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
	 */

	 /* Move raw CRT to just before the signature. */

	len += sig_and_oid_len;
	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	return len;
}

X509CertWriter::X509CertWriter() :
	ObjBase(new mbedtls_x509write_cert, &FreeObject),
	m_ca()
{
	mbedtls_x509write_crt_init(Get());
}

// Self-signed certificate.
X509CertWriter::X509CertWriter(HashType hashType, AsymKeyBase & prvKey, const std::string & subjName) :
	X509CertWriter()
{
	prvKey.NullCheck();

	mbedtls_x509write_crt_set_version(Get(), MBEDTLS_X509_CRT_VERSION_3);

	mbedtls_x509write_crt_set_md_alg(Get(), detail::GetMsgDigestType(hashType));

	mbedtls_x509write_crt_set_issuer_key(Get(), prvKey.Get());
	mbedtls_x509write_crt_set_subject_key(Get(), prvKey.Get());

	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_subject_name, Get(), subjName.c_str());
	detail::Asn1DeepCopy(Get()->issuer, *Get()->subject);
}

// Issue certificate
X509CertWriter::X509CertWriter(HashType hashType, const X509Cert & caCert, AsymKeyBase & prvKey, AsymKeyBase & pubKey, const std::string & subjName) :
	X509CertWriter()
{
	caCert.NullCheck();
	prvKey.NullCheck();
	pubKey.NullCheck();

	m_ca = detail::make_unique<X509Cert>(caCert);

	mbedtls_x509write_crt_set_version(Get(), MBEDTLS_X509_CRT_VERSION_3);

	mbedtls_x509write_crt_set_md_alg(Get(), detail::GetMsgDigestType(hashType));

	mbedtls_x509write_crt_set_issuer_key(Get(), prvKey.Get());
	mbedtls_x509write_crt_set_subject_key(Get(), pubKey.Get());

	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_subject_name, Get(), subjName.c_str());

	detail::Asn1DeepCopy(Get()->issuer, caCert.Get()->subject);
}

X509CertWriter::~X509CertWriter()
{
}

void X509CertWriter::SetSerialNum(const BigNumber & serialNum)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_serial, Get(), serialNum.Get());
}

void X509CertWriter::SetValidationTime(const std::string & validSince, const std::string & expireAfter)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_validity, Get(), validSince.c_str(), expireAfter.c_str());
}

void X509CertWriter::SetBasicConstraints(bool isCa, int maxChainDepth)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_basic_constraints, Get(), isCa, maxChainDepth);
}

void X509CertWriter::SetKeyUsage(unsigned int keyUsage)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_key_usage, Get(), keyUsage);
}

void X509CertWriter::SetNsType(unsigned char nsType)
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_ns_cert_type, Get(), nsType);
}

void X509CertWriter::SetV3Extensions(const std::map<std::string, std::pair<bool, std::string> >& v3ExtMap)
{
	for (const auto& item : v3ExtMap)
	{
		CALL_MBEDTLS_C_FUNC(mbedtls_x509write_crt_set_extension, Get(),
			item.first.data(), item.first.size(),
			item.second.first,
			reinterpret_cast<const uint8_t*>(item.second.second.data()), item.second.second.size());
	}
}

std::vector<uint8_t> X509CertWriter::GenerateDer(RbgBase & rbg)
{
	std::vector<uint8_t> der(EstimateX509CertDerSize(*Get()));

	int len = mbedtls_x509write_crt_der_new_ver(Get(), der.data(), der.size(), &RbgBase::CallBack, &rbg);
	if (len < 0)
	{
		throw Decent::MbedTlsObj::MbedTlsException("mbedtls_x509write_csr_der", len);
	}

	size_t gap = der.size() - len;

	std::memmove(der.data(), der.data() + gap, len);

	der.resize(len);

	return der;
}

std::string X509CertWriter::GeneratePem(RbgBase & rbg)
{
	std::vector<uint8_t> der = GenerateDer(rbg);

	size_t pemLen = detail::CalcPemMaxBytes(der.size(), PEM_CRT_HEADER_SIZE, PEM_CRT_FOOTER_SIZE);
	std::string pem(pemLen, '\0');

	size_t olen = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, PEM_BEGIN_CRT, PEM_END_CRT,
		der.data(), der.size(),
		reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

	pem.resize(olen);

	for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

	return pem;
}

std::string X509CertWriter::GeneratePemChain(RbgBase & rbg)
{
	if (m_ca)
	{
		return GeneratePem(rbg) + m_ca->GetPemChain();
	}
	else
	{
		return GeneratePem(rbg);
	};
}

void X509Cert::FreeObject(mbedtls_x509_crt * ptr)
{
	mbedtls_x509_crt_free(ptr);
	delete ptr;
}

X509Cert::X509Cert(const X509Cert & rhs) :
	X509Cert()
{
	rhs.NullCheck();

	const mbedtls_x509_crt* rhsCurr = rhs.Get();

	while (rhsCurr != nullptr)
	{
		CALL_MBEDTLS_C_FUNC(mbedtls_x509_crt_parse_der, Get(), rhsCurr->raw.p, rhsCurr->raw.len);
		rhsCurr = rhsCurr->next;
	}
}

X509Cert::X509Cert(X509Cert && rhs) :
	ObjBase(std::forward<ObjBase>(rhs)),
	m_currCert(std::move(rhs.m_currCert)),
	m_certStack(std::move(rhs.m_certStack))
{
	rhs.m_currCert = nullptr;
}

X509Cert::X509Cert(const std::string & pem) :
	X509Cert()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509_crt_parse, Get(), reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1);
}

X509Cert::X509Cert(const std::vector<uint8_t>& der) :
	X509Cert()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509_crt_parse, Get(), der.data(), der.size());
}

X509Cert::X509Cert(mbedtls_x509_crt & ref) :
	X509Cert(&ref, &ObjBase::DoNotFree)
{
}

X509Cert::~X509Cert()
{
}

X509Cert & X509Cert::operator=(X509Cert && rhs)
{
	ObjBase::operator=(std::forward<ObjBase>(rhs));

	if (this != &rhs)
	{
		m_currCert = std::move(rhs.m_currCert);
		m_certStack = std::move(rhs.m_certStack);

		rhs.m_currCert = nullptr;
	}
	return *this;
}

bool X509Cert::IsNull() const
{
	return ObjBase::IsNull() || (m_currCert == nullptr);
}

mbedtls_x509_crt * X509Cert::GetCurr()
{
	return m_currCert;
}

const mbedtls_x509_crt * X509Cert::GetCurr() const
{
	return m_currCert;
}

std::vector<uint8_t> X509Cert::GetCurrDer() const
{
	NullCheck();

	return std::vector<uint8_t>(GetCurr()->raw.p, GetCurr()->raw.p + GetCurr()->raw.len);
}

std::string X509Cert::GetCurrPem() const
{
	NullCheck();

	return GetPemByRef(*GetCurr());
}

std::string X509Cert::GetPemChain() const
{
	NullCheck();

	std::string pemChain;

	const mbedtls_x509_crt* curr = Get();

	while (curr != nullptr)
	{
		pemChain += GetPemByRef(*curr);
		curr = curr->next;
	}

	return pemChain;
}

mbedtls_pk_context & X509Cert::GetCurrPublicKey()
{
	NullCheck();

	return GetCurr()->pk;
}

HashType X509Cert::GetCurrHashType() const
{
	NullCheck();

	return detail::GetMsgDigestType(GetCurr()->sig_md);
}

std::string X509Cert::GetCurrCommonName() const
{
	NullCheck();

	const mbedtls_asn1_named_data& cnData = detail::Asn1FindNamedData(GetCurr()->subject, MBEDTLS_OID_AT_CN);

	return std::string(reinterpret_cast<const char*>(cnData.val.p),
		cnData.val.len);
}

void X509Cert::VerifyCurrSignature(AsymKeyBase & pubKey) const
{
	NullCheck();

	auto mdInfo = mbedtls_md_info_from_type(GetCurr()->sig_md);

	size_t hashLen = mbedtls_md_get_size(mdInfo);

	std::unique_ptr<uint8_t[]> hash = detail::make_unique<uint8_t[]>(hashLen);

	CALL_MBEDTLS_C_FUNC(mbedtls_md, mdInfo, GetCurr()->tbs.p, GetCurr()->tbs.len, hash.get());
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_verify_ext, GetCurr()->sig_pk, GetCurr()->sig_opts, pubKey.Get(),
		GetCurr()->sig_md, hash.get(), hashLen, GetCurr()->sig.p, GetCurr()->sig.len);
}

void X509Cert::VerifyCurrSignature()
{
	NullCheck();

	auto mdInfo = mbedtls_md_info_from_type(GetCurr()->sig_md);

	size_t hashLen = mbedtls_md_get_size(mdInfo);

	std::unique_ptr<uint8_t[]> hash = detail::make_unique<uint8_t[]>(hashLen);

	CALL_MBEDTLS_C_FUNC(mbedtls_md, mdInfo, GetCurr()->tbs.p, GetCurr()->tbs.len, hash.get());
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_verify_ext, GetCurr()->sig_pk, GetCurr()->sig_opts, &GetCurr()->pk,
		GetCurr()->sig_md, hash.get(), hashLen, GetCurr()->sig.p, GetCurr()->sig.len);
}

std::map<std::string, std::pair<bool, std::string> > X509Cert::GetCurrV3Extensions() const
{
	NullCheck();

	std::map<std::string, std::pair<bool, std::string> > extMap;

	int mbedRet = 0;
	int is_critical = 0;
	size_t len = 0;

	unsigned char *end_ext_data = nullptr;
	unsigned char *end_ext_octet = nullptr;

	unsigned char *begin = Get()->v3_ext.p;
	const unsigned char *end = Get()->v3_ext.p + Get()->v3_ext.len;

	unsigned char **p = &begin;

	char* oidPtr = nullptr;
	size_t oidSize = 0;

	char* extDataPtr = nullptr;
	size_t extDataSize = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (*p + len != end)
	{
		throw MbedTlsException("GetCurrV3Extensions", MBEDTLS_ERR_ASN1_INVALID_LENGTH);
	}

	while (*p < end)
	{
		is_critical = 0; /* DEFAULT FALSE */

		CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

		end_ext_data = *p + len;

		/* Get extension ID */
		CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OID);

		oidPtr = reinterpret_cast<char*>(*p);
		oidSize = len;

		*p += len;

		/* Get optional critical */
		mbedRet = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical);
		if (mbedRet != MBEDTLS_SUCCESS_RET && mbedRet != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
		{
			throw MbedTlsException("mbedtls_asn1_get_bool", mbedRet);
		}

		/* Data should be octet string type */
		CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING);

		extDataPtr = reinterpret_cast<char*>(*p);
		extDataSize = len;

		end_ext_octet = *p + len;

		if (end_ext_octet != end_ext_data)
		{
			throw MbedTlsException("GetCurrV3Extensions", MBEDTLS_ERR_ASN1_INVALID_LENGTH);
		}

		//Insert into the map.
		extMap.insert(
			std::make_pair(std::string(oidPtr, oidSize),
				std::make_pair(is_critical != 0, std::string(extDataPtr, extDataSize))));

		*p = end_ext_octet;
	}

	return extMap;
}

std::pair<bool, std::string> X509Cert::GetCurrV3Extension(const std::string & oid) const
{
	NullCheck();

	int mbedRet = 0;
	int is_critical = 0;
	size_t len = 0;

	unsigned char *end_ext_data = nullptr;
	unsigned char *end_ext_octet = nullptr;

	unsigned char *begin = Get()->v3_ext.p;
	const unsigned char *end = Get()->v3_ext.p + Get()->v3_ext.len;

	unsigned char **p = &begin;

	char* oidPtr = nullptr;
	size_t oidSize = 0;

	char* extDataPtr = nullptr;
	size_t extDataSize = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (*p + len != end)
	{
		throw MbedTlsException("GetCurrV3Extensions", MBEDTLS_ERR_ASN1_INVALID_LENGTH);
	}

	while (*p < end)
	{
		is_critical = 0; /* DEFAULT FALSE */

		CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

		end_ext_data = *p + len;

		/* Get extension ID */
		CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OID);

		oidPtr = reinterpret_cast<char*>(*p);
		oidSize = len;

		if (oidSize == oid.size() &&
			std::memcmp(oidPtr, oid.c_str(), oid.size()) == 0)
		{
			// The extension with given OID is found.

			*p += len;

			/* Get optional critical */
			mbedRet = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical);
			if (mbedRet != MBEDTLS_SUCCESS_RET && mbedRet != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
			{
				throw MbedTlsException("mbedtls_asn1_get_bool", mbedRet);
			}

			/* Data should be octet string type */
			CALL_MBEDTLS_C_FUNC(mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING);

			extDataPtr = reinterpret_cast<char*>(*p);
			extDataSize = len;

			end_ext_octet = *p + len;

			if (end_ext_octet != end_ext_data)
			{
				throw MbedTlsException("GetCurrV3Extensions", MBEDTLS_ERR_ASN1_INVALID_LENGTH);
			}

			return std::make_pair(is_critical != 0, std::string(extDataPtr, extDataSize));
		}

		*p = end_ext_data;
	}

	throw RuntimeException("The given OID is not found in the extension list.");
}

void X509Cert::VerifyChainWithCa(X509Cert & ca, mbedtls_x509_crl * crl, const char * cn, uint32_t & flags,
	const mbedtls_x509_crt_profile & prof, VerifyFunc vrfyFunc, void * vrfyParam)
{
	NullCheck();

	CALL_MBEDTLS_C_FUNC(mbedtls_x509_crt_verify_with_profile, Get(), ca.Get(), crl,
		&prof, cn, &flags, vrfyFunc, vrfyParam);
}

bool X509Cert::NextCert()
{
	if (m_currCert != nullptr && m_currCert->next != nullptr)
	{
		m_certStack.push_back(m_currCert);
		m_currCert = m_currCert->next;
		return true;
	}
	return false;
}

bool X509Cert::PrevCert()
{
	if (m_certStack.size() > 0)
	{
		m_currCert = m_certStack.back();
		m_certStack.pop_back();
		return true;
	}
	return false;
}

void X509Cert::GoToFirstCert()
{
	while (PrevCert()) {}
}

void X509Cert::GoToLastCert()
{
	while (NextCert()) {}
}

X509Cert::X509Cert() :
	ObjBase(new mbedtls_x509_crt, &FreeObject),
	m_currCert(Get()),
	m_certStack()
{
	mbedtls_x509_crt_init(Get());
}

X509Cert::X509Cert(mbedtls_x509_crt * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc),
	m_currCert(Get()),
	m_certStack()
{
}
