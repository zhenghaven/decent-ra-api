#pragma
#ifndef DECENT_CRYPTO_MANAGER_H
#define DECENT_CRYPTO_MANAGER_H

#include "SGXCryptoManager.h"
#include <sgx_tcrypto.h>
//struct _sgx_ec256_private_t;
//typedef _sgx_ec256_private_t sgx_ec256_private_t;
//struct _sgx_ec256_public_t;
//typedef _sgx_ec256_public_t sgx_ec256_public_t;

class DecentCryptoManager : public SGXCryptoManager
{
public:
	DecentCryptoManager();

	~DecentCryptoManager();

	virtual void SetSignPriKey(const sgx_ec256_private_t& inKey);
	virtual void SetSignPubKey(const sgx_ec256_public_t& inKey);

	virtual void SetEncrPriKey(const sgx_ec256_private_t& inKey);
	virtual void SetEncrPubKey(const sgx_ec256_public_t& inKey);

	virtual void SetProtoSignPubKey(const sgx_ec256_public_t& inKey);
	virtual const sgx_ec256_public_t& GetProtoSignPubKey();

private:
	sgx_ec256_public_t m_protoSignPubKey;
	//sgx_ec256_public_t m_encrPubKey;
};

#endif // !DECENT_CRYPTO_MANAGER_H
