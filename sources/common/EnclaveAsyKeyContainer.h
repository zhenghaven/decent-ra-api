#pragma once

#include <sgx_tcrypto.h>

struct EnclaveAsyKeyContainer
{
public:
	static EnclaveAsyKeyContainer& GetInstance();

	EnclaveAsyKeyContainer();

	virtual ~EnclaveAsyKeyContainer();

	virtual void Clear();

	sgx_ec256_private_t m_signPriKey;

	sgx_ec256_public_t m_signPubKey;

	sgx_status_t m_status;
};

