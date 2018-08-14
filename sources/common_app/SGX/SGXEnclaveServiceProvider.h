#pragma once

#include "SGXEnclave.h"
#include "SGXServiceProvider.h"

class SGXEnclaveServiceProvider : public SGXEnclave, public SGXServiceProvider
{
public:
	SGXEnclaveServiceProvider() = delete;

	SGXEnclaveServiceProvider(const std::string& enclavePath, const std::string& tokenPath, IASConnector ias);
	SGXEnclaveServiceProvider(const std::string& enclavePath, const fs::path tokenPath, IASConnector ias);
	SGXEnclaveServiceProvider(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName, IASConnector ias);

	virtual ~SGXEnclaveServiceProvider();

	//virtual std::string GetRASenderID() const override;
	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) override;
	//virtual sgx_status_t GetRASPEncrPubKey(sgx_ec256_public_t& outKey) override;

	virtual void InitSPRAEnvironment() override;
	virtual sgx_status_t GetIasReportNonce(const std::string & clientID, std::string& outNonce) override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const sgx_ra_msg3_t& inMsg3, const uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign) override;

private:
};
