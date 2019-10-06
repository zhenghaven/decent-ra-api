#include "X509Req.h"

#include <mbedtls/x509_csr.h>
#include <mbedtls/pem.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>

#include "MbedTlsException.h"
#include "AsymKeyBase.h"
#include "RbgBase.h"
#include "Internal/Pem.h"
#include "Internal/Hasher.h"
#include "Internal/make_unique.h"
#include "Internal/Asn1SizeEstimators.h"

using namespace Decent::MbedTlsObj;

namespace
{
	static constexpr char const PEM_BEGIN_CSR[] = "-----BEGIN CERTIFICATE REQUEST-----\n";
	static constexpr char const PEM_END_CSR[] = "-----END CERTIFICATE REQUEST-----\n";

	static constexpr size_t PEM_CSR_HEADER_SIZE = sizeof(PEM_BEGIN_CSR) - 1;
	static constexpr size_t PEM_CSR_FOOTER_SIZE = sizeof(PEM_END_CSR) - 1;
}

void X509ReqWriter::FreeObject(mbedtls_x509write_csr * ptr)
{
	mbedtls_x509write_csr_free(ptr);
	delete ptr;
}

size_t X509ReqWriter::EstimateX509ReqDerSize(mbedtls_x509write_csr & ctx)
{
	const char *sig_oid;
	size_t sig_oid_len = 0;
	size_t pub_len = 0, sig_and_oid_len = 0;
	size_t len = 0;
	mbedtls_pk_type_t pk_alg;

	/*
	 * Prepare data to be signed in tmp_buf
	 */

	using namespace detail;

	len += mbedtls_x509_write_extensions_est_size(ctx.extensions);

	if (len)
	{
		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);

		len += mbedtls_asn1_write_oid_est_size(MBEDTLS_OID_PKCS9_CSR_EXT_REQ, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ));

		len += mbedtls_asn1_write_len_est_size(len);
		len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	}

	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);

	if (!ctx.key)
	{
		throw MbedTlsException("EstimateX509ReqSize", MBEDTLS_ERR_PK_BAD_INPUT_DATA);
	}

	len += AsymKeyBase::EstimatePublicKeyDerSize(*ctx.key);

	/*
	 *  Subject  ::=  Name
	 */
	len += mbedtls_x509_write_names_est_size(ctx.subject);

	/*
	 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */
	len += mbedtls_asn1_write_int_est_size(0);

	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	/*
	 * Prepare signature
	 */
	const size_t hashLen = mbedtls_md_get_size(mbedtls_md_info_from_type(ctx.md_alg));

	const size_t signLen = AsymKeyBase::EstimateDerSignatureSize(*ctx.key, hashLen);

	if (mbedtls_pk_can_do(ctx.key, MBEDTLS_PK_RSA))
		pk_alg = MBEDTLS_PK_RSA;
	else if (mbedtls_pk_can_do(ctx.key, MBEDTLS_PK_ECDSA))
		pk_alg = MBEDTLS_PK_ECDSA;
	else
		throw MbedTlsException("EstimateX509ReqSize", MBEDTLS_ERR_X509_INVALID_ALG);

	CALL_MBEDTLS_C_FUNC(mbedtls_oid_get_oid_by_sig_alg, pk_alg, ctx.md_alg, &sig_oid, &sig_oid_len);

	/*
	 * Write data to output buffer
	 */
	sig_and_oid_len += mbedtls_x509_write_sig_est_size(sig_oid, sig_oid_len, signLen);

	len += sig_and_oid_len;
	len += mbedtls_asn1_write_len_est_size(len);
	len += mbedtls_asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

	return len;
}

X509ReqWriter::X509ReqWriter() :
	ObjBase(new mbedtls_x509write_csr, &FreeObject)
{
	mbedtls_x509write_csr_init(Get());
}

X509ReqWriter::X509ReqWriter(HashType hashType, AsymKeyBase & keyPair, const std::string & subjName) :
	X509ReqWriter()
{
	mbedtls_x509write_csr_set_key(Get(), keyPair.Get());
	mbedtls_x509write_csr_set_md_alg(Get(), detail::GetMsgDigestType(hashType));

	CALL_MBEDTLS_C_FUNC(mbedtls_x509write_csr_set_subject_name, Get(), subjName.c_str());
}

X509ReqWriter::~X509ReqWriter()
{
}

std::vector<uint8_t> X509ReqWriter::GenerateDer(RbgBase& rbg)
{
	std::vector<uint8_t> der(EstimateX509ReqDerSize(*Get()));

	int len = mbedtls_x509write_csr_der(Get(), der.data(), der.size(), &RbgBase::CallBack, &rbg);
	if (len < 0)
	{
		throw Decent::MbedTlsObj::MbedTlsException("mbedtls_x509write_csr_der", len);
	}

	size_t gap = der.size() - len;

	std::memmove(der.data(), der.data() + gap, len);

	der.resize(len);

	return der;
}

std::string X509ReqWriter::GeneratePem(RbgBase & rbg)
{
	std::vector<uint8_t> der = GenerateDer(rbg);

	size_t pemLen = detail::CalcPemMaxBytes(der.size(), PEM_CSR_HEADER_SIZE, PEM_CSR_FOOTER_SIZE);
	std::string pem(pemLen, '\0');

	size_t olen = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, PEM_BEGIN_CSR, PEM_END_CSR,
		der.data(), der.size(),
		reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

	pem.resize(olen);

	return pem;
}

void X509Req::FreeObject(mbedtls_x509_csr * ptr)
{
	mbedtls_x509_csr_free(ptr);
	delete ptr;
}

X509Req::X509Req(X509Req && rhs) :
	ObjBase(std::forward<ObjBase>(rhs))
{
}

X509Req::X509Req(const std::string & pem) :
	X509Req()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509_csr_parse, Get(), reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1);
}

X509Req::X509Req(const std::vector<uint8_t>& der) :
	X509Req()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509_csr_parse, Get(), der.data(), der.size());
}

X509Req::~X509Req()
{
}

X509Req & X509Req::operator=(X509Req && rhs)
{
	ObjBase::operator=(std::forward<ObjBase>(rhs));
	return *this;
}

std::string X509Req::GetPem() const
{
	NullCheck();

	size_t pemLen = detail::CalcPemMaxBytes(Get()->raw.len, PEM_CSR_HEADER_SIZE, PEM_CSR_FOOTER_SIZE);
	std::string pem(pemLen, '\0');

	size_t olen = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, PEM_BEGIN_CSR, PEM_END_CSR,
		Get()->raw.p, Get()->raw.len,
		reinterpret_cast<uint8_t*>(&pem[0]), pem.size(),
		&olen);

	pem.resize(olen);

	return pem;
}

std::vector<uint8_t> X509Req::GetDer() const
{
	NullCheck();

	return std::vector<uint8_t>(Get()->raw.p, Get()->raw.p + Get()->raw.len);
}

mbedtls_pk_context& X509Req::GetPublicKey()
{
	NullCheck();

	return Get()->pk;
}

HashType X509Req::GetHashType() const
{
	NullCheck();

	return detail::GetMsgDigestType(mbedtls_md_get_type(mbedtls_md_info_from_type(Get()->sig_md)));
}

void X509Req::VerifySignature(AsymKeyBase & pubKey) const
{
	NullCheck();

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(Get()->sig_md);
	const size_t mdSize = mbedtls_md_get_size(mdInfo);

	std::unique_ptr<uint8_t[]> tmpHash = detail::make_unique<uint8_t[]>(mdSize);

	CALL_MBEDTLS_C_FUNC(mbedtls_md, mdInfo, Get()->cri.p, Get()->cri.len, tmpHash.get());
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_verify_ext, Get()->sig_pk, Get()->sig_opts, pubKey.Get(),
		Get()->sig_md, tmpHash.get(), mdSize, Get()->sig.p, Get()->sig.len);
}

void X509Req::VerifySignature()
{
	NullCheck();

	const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(Get()->sig_md);
	const size_t mdSize = mbedtls_md_get_size(mdInfo);

	std::unique_ptr<uint8_t[]> tmpHash = detail::make_unique<uint8_t[]>(mdSize);

	CALL_MBEDTLS_C_FUNC(mbedtls_md, mdInfo, Get()->cri.p, Get()->cri.len, tmpHash.get());
	CALL_MBEDTLS_C_FUNC(mbedtls_pk_verify_ext, Get()->sig_pk, Get()->sig_opts, &Get()->pk,
		Get()->sig_md, tmpHash.get(), mdSize, Get()->sig.p, Get()->sig.len);
}

X509Req::X509Req() :
	ObjBase(new mbedtls_x509_csr, &FreeObject)
{
	mbedtls_x509_csr_init(Get());
}

X509Req::X509Req(mbedtls_x509_csr * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc)
{
}
