#include "DecentCryptoManager.h"

#include <cstring>


DecentCryptoManager::DecentCryptoManager() :
	RACryptoManager()
{
	SetProtoSignPubKey(GetSignPubKey());
}

DecentCryptoManager::~DecentCryptoManager()
{
}

void DecentCryptoManager::SetSignPriKey(const sgx_ec256_private_t & inKey)
{
	std::memcpy(&m_signPriKey, &inKey, sizeof(sgx_ec256_private_t));
}

void DecentCryptoManager::SetSignPubKey(const sgx_ec256_public_t & inKey)
{
	std::memcpy(&m_signPubKey, &inKey, sizeof(sgx_ec256_public_t));
}

void DecentCryptoManager::SetProtoSignPubKey(const sgx_ec256_public_t & inKey)
{
	std::memcpy(&m_protoSignPubKey, &inKey, sizeof(sgx_ec256_public_t));
}

const sgx_ec256_public_t & DecentCryptoManager::GetProtoSignPubKey()
{
	return m_protoSignPubKey;
}

