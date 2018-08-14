#include "OpenSSLTools.h"

#include <openssl/ec.h>
#include <openssl/pem.h>


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
