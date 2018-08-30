#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#pragma once

#include "SGXEnclave.h"
#include "SGXServiceProviderBase.h"
#include "../EnclaveServiceProviderBase.h"

class SGXEnclaveServiceProvider : public SGXEnclave, virtual public SGXServiceProviderBase, virtual public EnclaveServiceProviderBase
{
public:
	SGXEnclaveServiceProvider() = delete;

	SGXEnclaveServiceProvider(const std::string& enclavePath, const std::string& tokenPath, IASConnector ias);
	SGXEnclaveServiceProvider(const std::string& enclavePath, const fs::path tokenPath, IASConnector ias);
	SGXEnclaveServiceProvider(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName, IASConnector ias);

	virtual ~SGXEnclaveServiceProvider();

	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) const override; /*This is used to suppress the warnning*/
	virtual std::shared_ptr<ClientRASession> GetRAClientSession(std::unique_ptr<Connection>& connection) override; /*This is used to suppress the warnning*/

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) const override;
	virtual std::shared_ptr<ServiceProviderRASession> GetRASPSession(std::unique_ptr<Connection>& connection) override;

	virtual sgx_status_t GetIasReportNonce(const std::string & clientID, std::string& outNonce) override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const std::vector<uint8_t> & inMsg3, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr) override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;

protected:
	const IASConnector m_ias;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
