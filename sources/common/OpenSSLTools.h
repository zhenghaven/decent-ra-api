#pragma once

#include <vector>
#include <string>
#include <map>

#include "GeneralKeyTypes.h"

typedef struct ec_key_st EC_KEY;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct X509_req_st X509_REQ;
typedef struct X509_name_st X509_NAME;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

template<typename T>
class OpenSSLObjWrapper
{
public:
	OpenSSLObjWrapper(T* ptr) :
		m_ptr(ptr)
	{}

	OpenSSLObjWrapper(const OpenSSLObjWrapper& other) = delete;
	OpenSSLObjWrapper(OpenSSLObjWrapper&& other)
	{
		this->~OpenSSLObjWrapper();
		this->m_ptr = other.m_ptr;
		other.m_ptr = nullptr;
	}

	virtual OpenSSLObjWrapper& operator=(const OpenSSLObjWrapper& other) = delete;
	virtual OpenSSLObjWrapper& operator=(OpenSSLObjWrapper&& other)
	{
		if (this != &other)
		{
			this->~OpenSSLObjWrapper();
			this->m_ptr = other.m_ptr;
			other.m_ptr = nullptr;
		}
		return *this;
	}

	virtual ~OpenSSLObjWrapper() {}

	virtual operator bool() const
	{
		return m_ptr;
	}

	T* GetInternalPtr() const
	{
		return m_ptr;
	}

	T* Release()
	{
		T* tmp = m_ptr;
		m_ptr = nullptr;
		return tmp;
	}

protected:
	T * m_ptr;
};

class ECKeyPair : public OpenSSLObjWrapper<EVP_PKEY>
{
public:
	ECKeyPair() = delete;
	ECKeyPair(EVP_PKEY* ptr, bool isOwner);
	ECKeyPair(const std::string& pemStr);
	ECKeyPair(const general_secp256r1_private_t& prv);
	ECKeyPair(const general_secp256r1_private_t& prv, const general_secp256r1_public_t& pub);
	virtual ~ECKeyPair();

	std::string ToPemString() const;
	bool ToGeneralPublicKey(general_secp256r1_public_t& outKey) const;
	bool ToGeneralPrivateKey(general_secp256r1_private_t& outKey) const;
	bool ToGeneralKeyPair(general_secp256r1_private_t& outPrv, general_secp256r1_public_t& outPub) const;

	EC_KEY* GetInternalECKey() const;

private:
	ECKeyPair(EC_KEY* keyPair);

	bool m_isOwner;
};

class ECKeyPublic : public OpenSSLObjWrapper<EVP_PKEY>
{
public:
	ECKeyPublic() = delete;
	ECKeyPublic(EVP_PKEY* ptr, bool isOwner);
	ECKeyPublic(const std::string& pemStr);
	ECKeyPublic(const general_secp256r1_public_t& pub);
	virtual ~ECKeyPublic();

	std::string ToPemString() const;
	bool ToGeneralPublicKey(general_secp256r1_public_t& outKey) const;

	EC_KEY* GetInternalECKey() const;

private:
	ECKeyPublic(EC_KEY* key);

	bool m_isOwner;
};

class X509NameWrapper : public OpenSSLObjWrapper<X509_NAME>
{
public:
	X509NameWrapper() = delete;
	X509NameWrapper(const std::map<std::string, std::string>& inNameMap);
	X509NameWrapper(const X509NameWrapper& other) = delete;
	virtual ~X509NameWrapper();
};

class X509Wrapper : public OpenSSLObjWrapper<X509>
{
public:
	X509Wrapper() = delete;
	X509Wrapper(const std::string& pemStr);
	X509Wrapper(BIO& pemStr);
	X509Wrapper(const ECKeyPair& prvKey, const long validTime, const long serialNum,
		const X509NameWrapper& x509Names, const std::map<int, std::string>& extMap);
	X509Wrapper(const X509Wrapper& caCert, const ECKeyPair& prvKey, const ECKeyPublic& pubKey, const long validTime, const long serialNum,
		const X509NameWrapper& x509Names, const std::map<int, std::string>& extMap);
	X509Wrapper(const X509Wrapper& other) = delete;
	virtual ~X509Wrapper();

	std::string ToPemString() const;
	const ECKeyPublic& GetPublicKey() const;
	bool VerifySignature() const;
	bool VerifySignature(const ECKeyPublic& pubKey) const;

protected:
	const std::string ParseExtensionString(int nid) const;

private:
	const ECKeyPublic k_pubKey;
};

class X509ReqWrapper : public OpenSSLObjWrapper<X509_REQ>
{
public:
	X509ReqWrapper() = delete;
	X509ReqWrapper(const std::string& pemStr);
	X509ReqWrapper(BIO& pemStr);
	X509ReqWrapper(const ECKeyPair& prvKey);
	X509ReqWrapper(const X509ReqWrapper& other) = delete;
	virtual ~X509ReqWrapper();

	std::string ToPemString() const;
	const ECKeyPublic& GetPublicKey() const;
	bool VerifySignature() const;
	bool VerifySignature(const ECKeyPublic& pubKey) const;

private:
	const ECKeyPublic k_pubKey;
};

//class SSLWrapper : public OpenSSLObjWrapper<SSL>
//{
//public:
//	SSLWrapper() = delete;
//	SSLWrapper(SSL* ptr, bool isOwner);
//	virtual ~SSLWrapper();
//
//private:
//	bool m_isOwner;
//};

//class SSLCTXWrapper : public OpenSSLObjWrapper<SSL_CTX>
//{
//public:
//	SSLCTXWrapper() = delete;
//	SSLCTXWrapper(SSL_CTX* ptr, bool isOwner);
//	virtual ~SSLCTXWrapper();
//
//private:
//	bool m_isOwner;
//};

void LoadX509CertsFromStr(std::vector<X509*>& outCerts, const std::string& certStr);

bool VerifyIasReportCert(X509* root, const std::vector<X509*>& certsInHeader);

bool VerifyIasReportSignature(const std::string& data, std::vector<uint8_t> signature, X509* cert);

void FreeX509Cert(X509** cert);

void FreeX509Cert(std::vector<X509*>& certs);
