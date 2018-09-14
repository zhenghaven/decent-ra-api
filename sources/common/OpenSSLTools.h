#pragma once

#include <vector>
#include <string>
#include <map>

typedef struct ec_key_st EC_KEY;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct X509_name_st X509_NAME;

template<typename T>
class OpenSSLObjWrapper
{
public:
	OpenSSLObjWrapper(T* ptr) :
		m_ptr(ptr)
	{}

	OpenSSLObjWrapper(const OpenSSLObjWrapper& other) = delete;
	OpenSSLObjWrapper(OpenSSLObjWrapper&& other) :
		m_ptr(other.m_ptr)
	{
		other.m_ptr = nullptr;
	}

	OpenSSLObjWrapper& operator=(const OpenSSLObjWrapper& other) = delete;
	OpenSSLObjWrapper& operator=(OpenSSLObjWrapper&& other)
	{
		if (this != &other)
		{
			this->m_ptr = other.m_ptr;
			other.m_ptr = nullptr;
		}
		return *this;
	}

	virtual ~OpenSSLObjWrapper() {}

	operator bool() const
	{
		return m_ptr;
	}

	T* GetInstance() const
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

class X509NameWrapper : public OpenSSLObjWrapper<X509_NAME>
{
public:
	X509NameWrapper() = delete;
	X509NameWrapper(const std::map<std::string, std::string>& inNameMap);
	X509NameWrapper(const X509NameWrapper& other) = delete;
	X509NameWrapper(X509NameWrapper&& other) :
		OpenSSLObjWrapper(std::move(other))
	{}
	X509NameWrapper& operator=(const X509NameWrapper& other) = delete;
	X509NameWrapper& operator=(X509NameWrapper&& other)
	{
		this->OpenSSLObjWrapper::operator=(std::move(other));
		return *this;
	}
	virtual ~X509NameWrapper();
};

class X509Wrapper : public OpenSSLObjWrapper<X509>
{
public:
	X509Wrapper() = delete;
	X509Wrapper(const std::string& pemStr);
	X509Wrapper(BIO* pemStr);
	X509Wrapper(X509* caCert, EVP_PKEY* prvKey, EVP_PKEY* pubKey, const long validTime, const long serialNum,
		const X509NameWrapper& x509Names, const std::map<int, std::string>& extMap);
	X509Wrapper(const X509Wrapper& other) = delete;
	X509Wrapper(X509Wrapper&& other) :
		OpenSSLObjWrapper(std::move(other))
	{}
	X509Wrapper& operator=(const X509Wrapper& other) = delete;
	X509Wrapper& operator=(X509Wrapper&& other)
	{
		this->OpenSSLObjWrapper::operator=(std::move(other));
		return *this;
	}
	virtual ~X509Wrapper();

	std::string ToPemString() const;
};

std::string ECKeyPubGetPEMStr(const EC_KEY* inKey);

EC_KEY* ECKeyPubFromPEMStr(const std::string& inPem);

void LoadX509CertsFromStr(std::vector<X509*>& outCerts, const std::string& certStr);

bool VerifyIasReportCert(X509* root, const std::vector<X509*>& certsInHeader);

bool VerifyIasReportSignature(const std::string& data, std::vector<uint8_t> signature, X509* cert);

void FreeX509Cert(X509** cert);

void FreeX509Cert(std::vector<X509*>& certs);
