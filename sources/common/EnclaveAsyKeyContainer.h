#pragma once

#include <sgx_tcrypto.h>
#include <memory>
#include <atomic>

struct PrivateKeyWrap
{
	sgx_ec256_private_t m_prvKey;

	PrivateKeyWrap()
	{}

	PrivateKeyWrap(const PrivateKeyWrap& other)
	{
		std::memcpy(&m_prvKey, &(other.m_prvKey), sizeof(sgx_ec256_private_t));
	}

	~PrivateKeyWrap()
	{
		std::memset(&m_prvKey, 0, sizeof(sgx_ec256_private_t));
	}
};

class EnclaveAsyKeyContainer
{
public:
	static EnclaveAsyKeyContainer& GetInstance();

	EnclaveAsyKeyContainer();

	virtual ~EnclaveAsyKeyContainer();

	virtual bool IsValid() const;

	virtual std::shared_ptr<const PrivateKeyWrap> GetSignPrvKey() const;

	virtual std::shared_ptr<const sgx_ec256_public_t> GetSignPubKey() const;

	virtual void UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const sgx_ec256_public_t> pub);

private:
	std::atomic<std::shared_ptr<const sgx_ec256_public_t>* > m_signPubKey;

	std::atomic<std::shared_ptr<const PrivateKeyWrap>* > m_signPriKey;

	//std::mutex m_updateLock;

	bool m_isValid;
};

