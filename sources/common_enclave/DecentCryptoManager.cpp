#include "DecentCryptoManager.h"

#include <cstring>


DecentCryptoManager::DecentCryptoManager() :
	SGXCryptoManager()
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

void DecentCryptoManager::SetEncrPriKey(const sgx_ec256_private_t & inKey)
{
	std::memcpy(&m_encrPriKey, &inKey, sizeof(sgx_ec256_private_t));
}

void DecentCryptoManager::SetEncrPubKey(const sgx_ec256_public_t & inKey)
{
	std::memcpy(&m_encrPubKey, &inKey, sizeof(sgx_ec256_public_t));
}

void DecentCryptoManager::SetProtoSignPubKey(const sgx_ec256_public_t & inKey)
{
	std::memcpy(&m_protoSignPubKey, &inKey, sizeof(sgx_ec256_public_t));
}

const sgx_ec256_public_t & DecentCryptoManager::GetProtoSignPubKey()
{
	return m_protoSignPubKey;
}

