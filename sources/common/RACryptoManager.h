#pragma
#ifndef RA_CRYPTO_MANAGER_H
#define RA_CRYPTO_MANAGER_H

#include <sgx_tcrypto.h>
//struct _sgx_ec256_private_t;
//typedef _sgx_ec256_private_t sgx_ec256_private_t;
//struct _sgx_ec256_public_t;
//typedef _sgx_ec256_public_t sgx_ec256_public_t;

class RACryptoManager
{
public:
	RACryptoManager();
	virtual ~RACryptoManager();

	virtual void SetSignKeySign(const sgx_ec256_signature_t& sign);
	virtual void SetEncrKeySign(const sgx_ec256_signature_t& sign);

	virtual const sgx_ecc_state_handle_t& GetECC() const;

	virtual const sgx_ec256_private_t& GetSignPriKey() const;
	virtual const sgx_ec256_private_t& GetEncrPriKey() const;

	virtual const sgx_ec256_public_t& GetSignPubKey() const;
	virtual const sgx_ec256_public_t& GetEncrPubKey() const;

	virtual const sgx_ec256_signature_t& GetSignKeySign() const;
	virtual const sgx_ec256_signature_t& GetEncrKeySign() const;

	virtual sgx_status_t GetStatus() const;

protected:
	sgx_ecc_state_handle_t m_eccContext;

	sgx_ec256_private_t m_signPriKey;
	sgx_ec256_private_t m_encrPriKey;

	sgx_ec256_public_t m_signPubKey;
	sgx_ec256_public_t m_encrPubKey;

	sgx_ec256_signature_t m_signKeySign;
	sgx_ec256_signature_t m_encrKeySign;

	sgx_status_t m_status;
};

#endif // !RA_CRYPTO_MANAGER_H
