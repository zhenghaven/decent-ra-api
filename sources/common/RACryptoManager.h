#pragma
#ifndef RA_CRYPTO_MANAGER_H
#define RA_CRYPTO_MANAGER_H

#include <sgx_error.h>

struct _sgx_ec256_private_t;
typedef _sgx_ec256_private_t sgx_ec256_private_t;
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;
typedef void* sgx_ecc_state_handle_t;
class EnclaveAsyKeyContainer;

class RACryptoManager
{
public:
	RACryptoManager();
	virtual ~RACryptoManager();

	virtual const sgx_ecc_state_handle_t& GetECC() const;

	virtual sgx_status_t GetStatus() const;

protected:
	EnclaveAsyKeyContainer& m_keyContainer;

	sgx_ecc_state_handle_t m_eccContext;

	sgx_status_t m_status;
};

#endif // !RA_CRYPTO_MANAGER_H
