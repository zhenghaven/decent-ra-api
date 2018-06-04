#pragma once

#include "../common_app/DecentSGXEnclave.h"

class ExampleEnclave : public DecentSGXEnclave
{
public:
	using DecentSGXEnclave::DecentSGXEnclave;

	virtual sgx_status_t GetRASignPubKey(sgx_ec256_public_t& outKey) override;
	//virtual sgx_status_t GetRAEncrPubKey(sgx_ec256_public_t& outKey) override;

	virtual sgx_status_t InitRAEnvironment() override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const sgx_ra_msg2_t& inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t& inContextID) override;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const sgx_ra_msg3_t& inMsg3, const uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign) override;
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ra_msg4_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, sgx_ra_context_t inContextID) override;
	virtual sgx_status_t TerminationClean() override;

private:

};
