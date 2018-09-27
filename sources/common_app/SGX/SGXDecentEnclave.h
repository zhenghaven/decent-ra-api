#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#pragma once

#include <sgx_quote.h>

#include "../DecentEnclave.h"
#include "SGXEnclaveServiceProvider.h"

typedef struct _spid_t sgx_spid_t;

class SGXDecentEnclave : public SGXEnclaveServiceProvider, virtual public DecentEnclave
{
public:
	SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const bool isFirstNode, const std::string& enclavePath, const std::string& tokenPath);
	SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const bool isFirstNode, const fs::path& enclavePath, const fs::path& tokenPath);
	SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const bool isFirstNode, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	virtual ~SGXDecentEnclave();

	//SGXEnclave overrided methods:
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID) override;
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ias_report_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign);

	//DecentEnclave methods:
	virtual std::string GetDecentSelfRAReport() const override;
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) override;
	virtual bool ProcessDecentProtoKeyMsg(const std::string& nodeID, Connection& connection, const std::string& jsonMsg) override;
	virtual bool SendProtocolKey(const std::string& nodeID, Connection& connection) override;
	virtual bool ProcessAppReportSignReq(const std::string& appId, Connection& connection, const std::string& jsonMsg, const char* appAttach) override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

protected:
	virtual std::string GenerateDecentSelfRAReport() override;

private:
	std::string m_selfRaReport;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
