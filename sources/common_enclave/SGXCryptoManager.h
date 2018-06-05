#pragma
#ifndef SGX_CRYPTO_MANAGER_H
#define SGX_CRYPTO_MANAGER_H

#include <sgx_tcrypto.h>
//struct _sgx_ec256_private_t;
//typedef _sgx_ec256_private_t sgx_ec256_private_t;
//struct _sgx_ec256_public_t;
//typedef _sgx_ec256_public_t sgx_ec256_public_t;

class SGXCryptoManager
{
public:
	SGXCryptoManager();
	~SGXCryptoManager();

	void SetSignKeySign(const sgx_ec256_signature_t& sign);
	void SetEncrKeySign(const sgx_ec256_signature_t& sign);

	const sgx_ecc_state_handle_t& GetECC() const;

	const sgx_ec256_private_t& GetSignPriKey() const;
	const sgx_ec256_private_t& GetEncrPriKey() const;

	const sgx_ec256_public_t& GetSignPubKey() const;
	const sgx_ec256_public_t& GetEncrPubKey() const;

	const sgx_ec256_signature_t& GetSignKeySign() const;
	const sgx_ec256_signature_t& GetEncrKeySign() const;

	sgx_status_t GetStatus() const;
private:
	sgx_ecc_state_handle_t m_eccContext;

	sgx_ec256_private_t m_signPriKey;
	sgx_ec256_private_t m_encrPriKey;

	sgx_ec256_public_t m_signPubKey;
	sgx_ec256_public_t m_encrPubKey;

	sgx_ec256_signature_t m_signKeySign;
	sgx_ec256_signature_t m_encrKeySign;

	sgx_status_t m_status;
};

#endif // !SGX_CRYPTO_MANAGER_H
