#pragma once

#include <sgx_tcrypto.h>
#include <memory>
#include <string>
#include <cstring>

class ECKeyPublic;
class ECKeyPair;

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
	static const std::shared_ptr<EnclaveAsyKeyContainer> GetInstance();
	static void SetInstance(std::shared_ptr<EnclaveAsyKeyContainer> instance);

	EnclaveAsyKeyContainer();

	virtual ~EnclaveAsyKeyContainer();

	virtual bool IsValid() const;

	virtual std::shared_ptr<const PrivateKeyWrap> GetSignPrvKey() const;

	virtual std::shared_ptr<const sgx_ec256_public_t> GetSignPubKey() const;

	virtual std::shared_ptr<const ECKeyPublic> GetSignPubKeyOpenSSL() const;

	virtual std::shared_ptr<const ECKeyPair> GetSignPrvKeyOpenSSL() const;

	//virtual std::shared_ptr<const std::string> GetSignPubPem() const;

	virtual void UpdateSignKeyPair(std::shared_ptr<const PrivateKeyWrap> prv, std::shared_ptr<const sgx_ec256_public_t> pub);

private:
	EnclaveAsyKeyContainer(std::pair<std::unique_ptr<sgx_ec256_public_t>, std::unique_ptr<PrivateKeyWrap> > keyPair);

	std::shared_ptr<const sgx_ec256_public_t> m_signPubKey;

	std::shared_ptr<const PrivateKeyWrap> m_signPriKey;

	std::shared_ptr<const ECKeyPublic> m_signPubKeyOpen;

	std::shared_ptr<const ECKeyPair> m_signPriKeyOpen;

	bool m_isValid;
};

