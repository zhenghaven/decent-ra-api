#include "OpenSSLTools.h"

#include <climits>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#include <sgx_trts.h>

#include "OpenSSLConversions.h"
#include "OpenSSLInitializer.h"

std::string ECKeyPubGetPEMStr(const EC_KEY * inKey)
{
	if (!inKey)
	{
		return std::string();
	}

	BIO *bioMem = BIO_new(BIO_s_mem());
	if (bioMem == nullptr)
	{
		return std::string();
	}

	int opensslRet = PEM_write_bio_EC_PUBKEY(bioMem, const_cast<EC_KEY *>(inKey));

	if (opensslRet != 1)
	{
		return std::string();
	}

	char* bioMemPtr = nullptr;
	size_t bioMemLen = BIO_get_mem_data(bioMem, &bioMemPtr);

	std::string res(bioMemPtr, bioMemLen);

	BIO_free(bioMem);

	return res;
}

EC_KEY* ECKeyPubFromPEMStr(const std::string & inPem)
{
	BIO *bioMem = BIO_new(BIO_s_mem());
	if (bioMem == nullptr)
	{
		return nullptr;
	}

	int opensslRet = BIO_puts(bioMem, inPem.c_str());
	if (opensslRet != inPem.size())
	{
		return nullptr;
	}

	EC_KEY* ret = PEM_read_bio_EC_PUBKEY(bioMem, nullptr, nullptr, nullptr);

	BIO_free(bioMem);

	return ret;
}

void LoadX509CertsFromStr(std::vector<X509*>& outCerts, const std::string& certStr)
{
	BIO* certBio;
	X509* cert;

	outCerts.clear();

	certBio = BIO_new_mem_buf((void*)certStr.c_str(), -1);
	if (!certBio)
	{
		return;
	}

	bool parseRes = true;
	while (parseRes)
	{
		cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
		if (cert != nullptr)
		{
			outCerts.push_back(cert);
		}
		else
		{
			parseRes = false;
		}
	}

	BIO_free_all(certBio);
}

bool VerifyIasReportCert(X509* root, const std::vector<X509*>& certsInHeader)
{
	int sslRes = 1;
	X509_STORE* store = X509_STORE_new();
	X509_STORE_add_cert(store, root);

	for (auto rit = certsInHeader.rbegin(); rit != certsInHeader.rend(); ++rit)
	{
		X509_STORE_CTX* ctx = X509_STORE_CTX_new();

		sslRes = X509_STORE_CTX_init(ctx, store, *rit, nullptr);
		if (sslRes != 1)
		{
			X509_STORE_CTX_cleanup(ctx);
			X509_STORE_free(store);
			return false;
		}

		sslRes = X509_verify_cert(ctx);
		if (sslRes != 1)
		{
			X509_STORE_CTX_cleanup(ctx);
			X509_STORE_free(store);
			return false;
		}

		X509_STORE_add_cert(store, *rit);

		X509_STORE_CTX_cleanup(ctx);
	}

	X509_STORE_free(store);
	return sslRes == 1;
}

bool VerifyIasReportSignature(const std::string& data, std::vector<uint8_t> signature, X509* cert)
{
	int sslRes = 1;

	EVP_PKEY * pubKey = X509_get_pubkey(cert);

	EVP_MD_CTX* rsaVerifyCtx = EVP_MD_CTX_create();

	if (EVP_DigestVerifyInit(rsaVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
	{
		return false;
	}
	if (EVP_DigestVerifyUpdate(rsaVerifyCtx, data.c_str(), data.length()) <= 0)
	{
		return false;
	}

	sslRes = EVP_DigestVerifyFinal(rsaVerifyCtx, signature.data(), signature.size());

	EVP_MD_CTX_free(rsaVerifyCtx);
	EVP_PKEY_free(pubKey);

	return sslRes == 1;
}

void FreeX509Cert(X509 ** cert)
{
	X509_free(*cert);
	*cert = nullptr;
}

void FreeX509Cert(std::vector<X509*>& certs)
{
	for (auto it = certs.begin(); it != certs.end(); ++it)
	{
		X509_free(*it);
	}
	certs.clear();
}

X509_NAME* ConstructX509NameList(const std::map<std::string, std::string>& inNameMap)
{
	X509_NAME* certName = X509_NAME_new();
	if (!certName)
	{
		return nullptr;
	}
	int opensslRet = 1;
	for (auto it = inNameMap.begin(); it != inNameMap.end() && opensslRet; ++it)
	{
		opensslRet = X509_NAME_add_entry_by_txt(certName, it->first.c_str(), MBSTRING_ASC, 
			reinterpret_cast<const uint8_t*>(it->second.c_str()), static_cast<int>(it->second.size()),
			-1, 0);
	}
	if (!opensslRet)
	{
		X509_NAME_free(certName);
		return nullptr;
	}
	
	return certName;
}

X509NameWrapper::X509NameWrapper(const std::map<std::string, std::string>& inNameMap) :
	OpenSSLObjWrapper(ConstructX509NameList(inNameMap))
{
}

X509NameWrapper::~X509NameWrapper()
{
	X509_NAME_free(m_ptr);
}

static int CertAddExtension(X509* cert, X509V3_CTX& ctx, int nid, const char* value)
{
	if (!cert || !value)
	{
		return 0;
	}

	X509_EXTENSION *ext = nullptr;
	int res = 1;
	ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
	if (!ext)
	{
		return 0;
	}
	res = X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return res;
}

static X509* ConstructX509Cert(X509 * caCert, EVP_PKEY * prvKey, EVP_PKEY * pubKey, const long validTime, const long serialNum, const X509NameWrapper & x509Names, const std::map<int, std::string>& extMap)
{
	if (!prvKey || !pubKey || !x509Names.GetInternalPtr())
	{
		return nullptr;
	}
	EC_KEY* testPrv = EVP_PKEY_get1_EC_KEY(prvKey);
	EC_KEY* testPub = EVP_PKEY_get1_EC_KEY(pubKey);
	if (!testPrv ||
		!testPub ||
		!EC_KEY_get0_private_key(testPrv) ||
		!EC_KEY_get0_public_key(testPub))
	{
		return nullptr;
	}
	if (caCert && !X509_verify(caCert, prvKey))
	{
		return nullptr;
	}

	X509* cert = X509_new();
	if (!cert)
	{
		return nullptr;
	}
	if (!caCert)
	{//Self Sign
		caCert = cert;
	}

	if (!X509_set_version(cert, 2) ||
		!X509_set_pubkey(cert, pubKey) ||
		!X509_set_subject_name(cert, x509Names.GetInternalPtr()) ||
		!X509_set_issuer_name(cert, X509_get_subject_name(caCert)))
	{
		X509_free(cert);
		return nullptr;
	}


	if (!ASN1_INTEGER_set(X509_get_serialNumber(cert), serialNum) ||
		!X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
		!X509_gmtime_adj(X509_get_notAfter(cert), validTime))
	{
		X509_free(cert);
		return nullptr;
	}

	X509V3_CTX ctx;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, caCert, cert, NULL, NULL, 0);

	int opensslRet = 1;
	for (auto it = extMap.begin(); it != extMap.end() && opensslRet; ++it)
	{
		opensslRet = CertAddExtension(cert, ctx, it->first, it->second.c_str());
	}
	if (!opensslRet)
	{
		X509_free(cert);
		return nullptr;
	}
	
	opensslRet = X509_sign(cert, prvKey, EVP_sha256());
	if (!opensslRet)
	{
		X509_free(cert);
		return nullptr;
	}
	else
	{
		return cert;
	}
}

#define DefConstructFromPemFunc(TypeX, FuncX) static TypeX* Construct_##FuncX(const std::string& pemStr) \
									   {\
										   if (!pemStr.size()) \
										   { \
											   return nullptr; \
										   } \
										   BIO* certBio = BIO_new_mem_buf(pemStr.c_str(), static_cast<int>(pemStr.size())); \
										   TypeX* cert = PEM_read_bio_##FuncX(certBio, nullptr, nullptr, nullptr); \
										   BIO_free_all(certBio);\
										   return cert;\
									   }

#define ToPemStringForType(FuncX, PTR) BIO* bio = BIO_new(BIO_s_mem()); \
									   if (!bio || !PEM_write_bio_##FuncX(bio, PTR)){ return std::string(); } \
									   char* bufPtr = nullptr; \
									   size_t len = BIO_get_mem_data(bio, &bufPtr); \
									   std::string res(bufPtr, len); \
									   BIO_free_all(bio);

DefConstructFromPemFunc(X509, X509)

static inline EVP_PKEY* GetPubkeyFromX509Const(const X509* cert)
{
	return cert ? X509_get0_pubkey(cert) : nullptr;
}

X509Wrapper::X509Wrapper(const std::string & pemStr) :
	OpenSSLObjWrapper(Construct_X509(pemStr)),
	k_pubKey(GetPubkeyFromX509Const(m_ptr), false)
{
}

X509Wrapper::X509Wrapper(BIO& pemStr) :
	OpenSSLObjWrapper(PEM_read_bio_X509(&pemStr, nullptr, nullptr, nullptr)),
	k_pubKey(GetPubkeyFromX509Const(m_ptr), false)
{
}

X509Wrapper::X509Wrapper(const ECKeyPair & prvKey, const long validTime, const long serialNum, const X509NameWrapper & x509Names, const std::map<int, std::string>& extMap) :
	OpenSSLObjWrapper(ConstructX509Cert(nullptr, prvKey.GetInternalPtr(), prvKey.GetInternalPtr(), validTime, serialNum, x509Names, extMap)),
	k_pubKey(GetPubkeyFromX509Const(m_ptr), false)
{
}

X509Wrapper::X509Wrapper(const X509Wrapper & caCert, const ECKeyPair & prvKey, const ECKeyPublic & pubKey, const long validTime, const long serialNum, const X509NameWrapper & x509Names, const std::map<int, std::string>& extMap) :
	OpenSSLObjWrapper(ConstructX509Cert(caCert.GetInternalPtr(), prvKey.GetInternalPtr(), pubKey.GetInternalPtr(), validTime, serialNum, x509Names, extMap)),
	k_pubKey(GetPubkeyFromX509Const(m_ptr), false)
{
}

X509Wrapper::~X509Wrapper()
{
	X509_free(m_ptr);
}

std::string X509Wrapper::ToPemString() const
{
	if (!m_ptr)
	{
		return std::string();
	}

	ToPemStringForType(X509, m_ptr);

	return res;
}

const ECKeyPublic & X509Wrapper::GetPublicKey() const
{
	return k_pubKey;
}

bool X509Wrapper::VerifySignature() const
{
	return VerifySignature(k_pubKey);
}

bool X509Wrapper::VerifySignature(const ECKeyPublic & pubKey) const
{
	return X509_verify(m_ptr, pubKey.GetInternalPtr()) == 1;
}

const std::string X509Wrapper::ParseExtensionString(int nid) const
{
	int extLoc = X509_get_ext_by_NID(m_ptr, nid, -1);
	if (extLoc == -1)
	{
		return std::string();
	}
	X509_EXTENSION *ext = X509_get_ext(m_ptr, extLoc);
	if (!ext)
	{
		return std::string();
	}

	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio ||
		!X509V3_EXT_print(bio, ext, 0, 0))
	{
		BIO_free_all(bio);
		return std::string();
	}

	BIO_flush(bio);
	char* bufPtr = nullptr;
	size_t len = BIO_get_mem_data(bio, &bufPtr);
	std::string res(bufPtr, len);
	BIO_free_all(bio);

	return res;
}

DefConstructFromPemFunc(X509_REQ, X509_REQ)

static inline EVP_PKEY* GetPubkeyFromX509ReqConst(X509_REQ* cert)
{
	return cert ? X509_REQ_get0_pubkey(cert) : nullptr;
}

X509ReqWrapper::X509ReqWrapper(const std::string & pemStr) :
	OpenSSLObjWrapper(Construct_X509_REQ(pemStr)),
	k_pubKey(GetPubkeyFromX509ReqConst(m_ptr), false)
{
}

X509ReqWrapper::X509ReqWrapper(BIO & pemStr) :
	OpenSSLObjWrapper(PEM_read_bio_X509_REQ(&pemStr, nullptr, nullptr, nullptr)),
	k_pubKey(GetPubkeyFromX509ReqConst(m_ptr), false)
{
}

static X509_REQ* ConstructX509Req(const ECKeyPair& prvKey)
{
	if (!prvKey)
	{
		return nullptr;
	}

	X509_REQ* ret = X509_REQ_new();
	if (!ret ||
		!X509_REQ_set_version(ret, 2) ||
		!X509_REQ_set_pubkey(ret, prvKey.GetInternalPtr()) ||
		!X509_REQ_sign(ret, prvKey.GetInternalPtr(), EVP_sha256()))
	{
		X509_REQ_free(ret);
		return nullptr;
	}

	return ret;
}

X509ReqWrapper::X509ReqWrapper(const ECKeyPair& prvKey) :
	OpenSSLObjWrapper(ConstructX509Req(prvKey)),
	k_pubKey(GetPubkeyFromX509ReqConst(m_ptr), false)
{
}

X509ReqWrapper::~X509ReqWrapper()
{
	X509_REQ_free(m_ptr);
}

std::string X509ReqWrapper::ToPemString() const
{
	if (!m_ptr)
	{
		return std::string();
	}

	ToPemStringForType(X509_REQ, m_ptr);

	return res;
}

const ECKeyPublic & X509ReqWrapper::GetPublicKey() const
{
	return k_pubKey;
}

bool X509ReqWrapper::VerifySignature() const
{
	return VerifySignature(k_pubKey);
}

bool X509ReqWrapper::VerifySignature(const ECKeyPublic & pubKey) const
{
	return X509_REQ_verify(m_ptr, pubKey.GetInternalPtr()) == 1;
}

DefConstructFromPemFunc(EC_KEY, ECPrivateKey)

static EVP_PKEY* ConstructPrivateKey(const std::string & pemStr)
{
	EC_KEY* ecKey = Construct_ECPrivateKey(pemStr);
	if (!ecKey)
	{
		return nullptr;
	}
	EVP_PKEY* pKey = EVP_PKEY_new();
	if (pKey && EVP_PKEY_assign_EC_KEY(pKey, ecKey))
	{
		return pKey;
	}
	return nullptr;
}

static EVP_PKEY* ConstructECKeyPair(EC_KEY* keyPair)
{
	if (!keyPair)
	{
		return nullptr;
	}

	EVP_PKEY* ret = EVP_PKEY_new();
	if (!ret ||
		!EVP_PKEY_assign_EC_KEY(ret, keyPair))
	{
		EVP_PKEY_free(ret);
		EC_KEY_free(keyPair);
		return nullptr;
	}

	return ret;
}

ECKeyPair::ECKeyPair(EVP_PKEY * ptr, bool isOwner) :
	OpenSSLObjWrapper(ptr),
	m_isOwner(isOwner)
{
}

ECKeyPair::ECKeyPair(const std::string & pemStr) :
	OpenSSLObjWrapper(ConstructPrivateKey(pemStr))
{
}

ECKeyPair::ECKeyPair(const general_secp256r1_private_t & prv) :
	ECKeyPair(ECKeyGeneral2OpenSSL(&prv, nullptr, nullptr))
{
}

ECKeyPair::ECKeyPair(const general_secp256r1_private_t & prv, const general_secp256r1_public_t & pub) :
	ECKeyPair(ECKeyGeneral2OpenSSL(&prv, &pub, nullptr))
{
}

ECKeyPair::ECKeyPair(EC_KEY* keyPair) :
	OpenSSLObjWrapper(ConstructECKeyPair(keyPair))
{
}

ECKeyPair::~ECKeyPair()
{
	if (m_isOwner)
	{
		EVP_PKEY_free(m_ptr);
	}
}

std::string ECKeyPair::ToPemString() const
{
	if (!m_ptr)
	{
		return std::string();
	}

	ToPemStringForType(EC_PUBKEY, GetInternalECKey());

	return res;
}

EC_KEY * ECKeyPair::GetInternalECKey() const
{
	if (!m_ptr)
	{
		return nullptr;
	}
	return EVP_PKEY_get0_EC_KEY(m_ptr);
}

DefConstructFromPemFunc(EC_KEY, EC_PUBKEY)

static EVP_PKEY* ConstructPublicKey(const std::string & pemStr)
{
	EC_KEY* ecKey = Construct_EC_PUBKEY(pemStr);
	if (!ecKey)
	{
		return nullptr;
	}
	EVP_PKEY* pKey = EVP_PKEY_new();
	if (pKey && EVP_PKEY_assign_EC_KEY(pKey, ecKey))
	{
		return pKey;
	}
	return nullptr;
}

ECKeyPublic::ECKeyPublic(EVP_PKEY * ptr, bool isOwner) :
	OpenSSLObjWrapper(ptr),
	m_isOwner(isOwner)
{
}

ECKeyPublic::ECKeyPublic(const std::string & pemStr) :
	OpenSSLObjWrapper(ConstructPublicKey(pemStr))
{
}

ECKeyPublic::ECKeyPublic(const general_secp256r1_public_t & pub) :
	ECKeyPublic(ECKeyGeneral2OpenSSL(&pub, nullptr))
{
}

ECKeyPublic::ECKeyPublic(EC_KEY * key) :
	OpenSSLObjWrapper(ConstructECKeyPair(key))
{
}

ECKeyPublic::~ECKeyPublic()
{
	if (m_isOwner)
	{
		EVP_PKEY_free(m_ptr);
	}
}

std::string ECKeyPublic::ToPemString() const
{
	if (!m_ptr)
	{
		return std::string();
	}

	ToPemStringForType(EC_PUBKEY, GetInternalECKey());

	return res;
}

EC_KEY * ECKeyPublic::GetInternalECKey() const
{
	if (!m_ptr)
	{
		return nullptr;
	}
	return EVP_PKEY_get0_EC_KEY(m_ptr);
}

static long GetDecentSerialNumber()
{
	long ret = 0;
	return sgx_read_rand(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)) == SGX_SUCCESS ? ret : 0;
}

DecentServerX509::DecentServerX509(const std::string & pemStr) :
	X509Wrapper(pemStr),
	k_platformType(ParsePlatformType()),
	k_selfRaReport(ParseSelfRaReport())
{
}

DecentServerX509::DecentServerX509(const ECKeyPair & prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport) :
	X509Wrapper(prvKey, 
		LONG_MAX, 
		GetDecentSerialNumber(), 
		X509NameWrapper(std::map<std::string, std::string>({
			std::pair<std::string, std::string>("CN", enclaveHash),
		})), 
		std::map<int, std::string>{
			std::pair<int, std::string>(NID_basic_constraints, "critical,CA:TRUE"),
			std::pair<int, std::string>(NID_key_usage, "critical,nonRepudiation,digitalSignature,keyAgreement,keyCertSign,cRLSign"),
			std::pair<int, std::string>(NID_ext_key_usage, "serverAuth,clientAuth"),
			std::pair<int, std::string>(NID_subject_key_identifier, "hash"),
			std::pair<int, std::string>(NID_netscape_cert_type, "sslCA,client,server"),
			std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID(), "critical," + platformType),
			std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetSelfRAReportNID(), "critical," + selfRaReport),
		}),
	k_platformType(platformType),
	k_selfRaReport(selfRaReport)
{
}

const std::string & DecentServerX509::GetPlatformType() const
{
	return k_platformType;
}

const std::string & DecentServerX509::GetSelfRaReport() const
{
	return k_selfRaReport;
}

const std::string DecentServerX509::ParsePlatformType() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID());
}

const std::string DecentServerX509::ParseSelfRaReport() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetSelfRAReportNID());
}

DecentAppX509::DecentAppX509(const std::string & pemStr) :
	X509Wrapper(pemStr),
	k_platformType(ParsePlatformType()),
	k_appId(ParseAppId())
{
}

DecentAppX509::DecentAppX509(const ECKeyPublic & pubKey, const DecentServerX509& caCert, const ECKeyPair & serverPrvKey, const std::string & enclaveHash, const std::string & platformType, const std::string & appId) :
	X509Wrapper(caCert, serverPrvKey, pubKey, 
		LONG_MAX,
		GetDecentSerialNumber(),
		X509NameWrapper(std::map<std::string, std::string>({
			std::pair<std::string, std::string>("CN", enclaveHash),
			})),
			std::map<int, std::string>{
	std::pair<int, std::string>(NID_basic_constraints, "critical,CA:TRUE"),
		std::pair<int, std::string>(NID_key_usage, "critical,nonRepudiation,digitalSignature,keyAgreement,keyCertSign,cRLSign"),
		std::pair<int, std::string>(NID_ext_key_usage, "serverAuth,clientAuth"),
		std::pair<int, std::string>(NID_subject_key_identifier, "hash"),
		std::pair<int, std::string>(NID_netscape_cert_type, "sslCA,client,server"),
		std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID(), "critical," + platformType),
		std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetLocalAttestationIdNID(), "critical," + appId),
	}),
	k_platformType(platformType),
	k_appId(appId)
{
}

const std::string & DecentAppX509::GetPlatformType() const
{
	return k_platformType;
}

const std::string & DecentAppX509::GetAppId() const
{
	return k_appId;
}

const std::string DecentAppX509::ParsePlatformType() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID());
}

const std::string DecentAppX509::ParseAppId() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetLocalAttestationIdNID());
}
