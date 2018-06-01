#pragma once

#include "../common_app/SGXEnclave.h"

class ExampleEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	virtual sgx_status_t GetRAPublicKey(sgx_ec256_public_t& outKey) override;

	virtual sgx_status_t SetRARemotePublicKey(sgx_ec256_public_t& outKey) override;

	virtual sgx_status_t EnclaveInitRA(int enablePSE, sgx_ra_context_t& outContextID) override;

	virtual sgx_status_t GetRAMsg1(sgx_ra_msg1_t& outMsg1, sgx_ra_context_t& inContextID) override;

	virtual sgx_status_t ProcessMsg1(const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;

	virtual sgx_status_t ProcessMsg2(const sgx_ra_msg2_t& inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, uint32_t& msg3Size, sgx_ra_context_t& inContextID) override;

	void TestEnclaveFunctions();

private:

};
