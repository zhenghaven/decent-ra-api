#pragma once

#include "../common_app/SGXEnclave.h"

class ExampleEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	virtual sgx_status_t GetRAPublicKey(sgx_ec256_public_t& outKey) override;

	virtual sgx_status_t SetSrvPrvRAPublicKey(sgx_ec256_public_t& outKey) override;

	virtual sgx_status_t EnclaveInitRA(int enablePSE, sgx_ra_context_t& outContextID) override;

	virtual sgx_status_t GetRAMsg1(sgx_ra_msg1_t& outMsg1, sgx_ra_context_t& inContextID) override;

	void TestEnclaveFunctions();

private:

};
