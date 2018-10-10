#include "OpenSSLTools.h"

#include <climits>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <sgx_trts.h>

#include "OpenSSLConversions.h"
#include "OpenSSLInitializer.h"

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
