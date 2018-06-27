#include "CryptoTools.h"

#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <cstdlib>
#include <vector>

#include <sgx_tcrypto.h>
#include <sgx_ecp_types.h>

#include <cppcodec/base64_rfc4648.hpp>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

std::string SerializePubKey(const sgx_ec256_public_t & pubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	std::memcpy(&buffer[0], &pubKey, sizeof(sgx_ec256_public_t));

	return cppcodec::base64_rfc4648::encode(buffer);
}

void DeserializePubKey(const std::string & inPubKeyStr, sgx_ec256_public_t & outPubKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_public_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inPubKeyStr);

	std::memcpy(&outPubKey, buffer.data(), sizeof(sgx_ec256_public_t));
}

std::string SerializeSignature(const sgx_ec256_signature_t & sign)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const char*>(&sign), sizeof(sgx_ec256_signature_t));
}

void DeserializeSignature(const std::string & inSignStr, sgx_ec256_signature_t & outSign)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec256_signature_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inSignStr);

	std::memcpy(&outSign, buffer.data(), sizeof(sgx_ec256_signature_t));
}

std::string SerializeKey(const sgx_ec_key_128bit_t & key)
{
	return cppcodec::base64_rfc4648::encode(reinterpret_cast<const char*>(&key), sizeof(sgx_ec_key_128bit_t));
}

void DeserializeKey(const std::string & inPubStr, sgx_ec_key_128bit_t & outKey)
{
	std::vector<uint8_t> buffer(sizeof(sgx_ec_key_128bit_t), 0);
	cppcodec::base64_rfc4648::decode(buffer, inPubStr);

	std::memcpy(&outKey, buffer.data(), sizeof(sgx_ec_key_128bit_t));
}

std::string SerializeStruct(const char * ptr, size_t size)
{
	return cppcodec::base64_rfc4648::encode(ptr, size);
}

void DeserializeStruct(const std::string & inStr, void * ptr, size_t size)
{
	std::vector<uint8_t> buffer(size, 0);
	cppcodec::base64_rfc4648::decode(buffer, inStr);

	std::memcpy(ptr, buffer.data(), size);
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
