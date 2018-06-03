#pragma once

#include "../common_app/SGXEnclave.h"

class ExampleEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	virtual sgx_status_t GetRAPublicKey(sgx_ec256_public_t& outKey) override;

	//virtual sgx_status_t SetRARemotePublicKey(sgx_ec256_public_t& outKey) override;

	//virtual sgx_status_t EnclaveInitRA(int enablePSE, sgx_ra_context_t& outContextID) override;

	//virtual sgx_status_t GetRAMsg1(sgx_ra_msg1_t& outMsg1, sgx_ra_context_t& inContextID) override;

	//virtual sgx_status_t ProcessMsg1(const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;

	//virtual sgx_status_t ProcessMsg2(const sgx_ra_msg2_t& inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t& inContextID) override;

	virtual sgx_status_t InitRAEnvironment() override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const sgx_ra_msg2_t& inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t& inContextID) override;
	virtual sgx_status_t TerminationClean() override;

private:

};
