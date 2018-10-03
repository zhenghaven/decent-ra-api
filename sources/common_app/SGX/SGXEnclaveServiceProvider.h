#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENTRALIZED_ENCLAVE_INTERNAL || USE_DECENT_ENCLAVE_SERVER_INTERNAL)

#include "SGXEnclave.h"
#include "SGXServiceProviderBase.h"
#include "../EnclaveServiceProviderBase.h"

#include <memory>

class IASConnector;

class SGXEnclaveServiceProvider : public SGXEnclave, virtual public SGXServiceProviderBase, virtual public EnclaveServiceProviderBase
{
public:
	SGXEnclaveServiceProvider() = delete;

	SGXEnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const std::string& tokenPath);
	SGXEnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const fs::path& enclavePath, const fs::path& tokenPath);
	SGXEnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	virtual ~SGXEnclaveServiceProvider();

	virtual const char* GetPlatformType() const override;
	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) const override; /*This is used to suppress the warnning*/
	virtual const std::string GetRAClientSignPubKey() const override; /*This is used to suppress the warnning*/
	virtual ClientRASession* GetRAClientSession(Connection& connection) override; /*This is used to suppress the warnning*/

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) const override;
	virtual const std::string GetRASPSignPubKey() const override;
	virtual ServiceProviderRASession* GetRASPSession(Connection& connection) override;

	virtual sgx_status_t GetIasReportNonce(const std::string & clientID, std::string& outNonce) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const std::vector<uint8_t> & inMsg3, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ias_report_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr) override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

protected:
	std::shared_ptr<const IASConnector> m_ias;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENTRALIZED_ENCLAVE_INTERNAL || USE_DECENT_ENCLAVE_SERVER_INTERNAL)
