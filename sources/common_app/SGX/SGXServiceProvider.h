#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#pragma once

#include "SGXServiceProviderBase.h"

#include <memory>

class IASConnector;

class SGXServiceProvider : virtual public SGXServiceProviderBase
{
public:
	SGXServiceProvider() = delete;

	SGXServiceProvider(const std::shared_ptr<IASConnector>& ias);

	virtual ~SGXServiceProvider(); 

	virtual const char* GetPlatformType() const override;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASPSession(std::unique_ptr<Connection>& connection) override;

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) const override;
	virtual const std::string GetRASPSignPubKey() const override;
	virtual sgx_status_t GetIasReportNonce(const std::string & clientID, std::string& outNonce);
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2);
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const std::vector<uint8_t> & inMsg3, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ias_report_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;

protected:
	std::shared_ptr<const IASConnector> m_ias;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
