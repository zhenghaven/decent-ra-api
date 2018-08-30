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
	SGXDecentEnclave(const sgx_spid_t& spid, IASConnector iasConnector, const bool isFirstNode, const std::string& enclavePath, const std::string& tokenPath);
	SGXDecentEnclave(const sgx_spid_t& spid, IASConnector iasConnector, const bool isFirstNode, const std::string& enclavePath, const fs::path tokenPath);
	SGXDecentEnclave(const sgx_spid_t& spid, IASConnector iasConnector, const bool isFirstNode, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	~SGXDecentEnclave();

	//SGXEnclave overrided methods:
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID) override;

	//Decentralized methods:
	virtual bool ToDecentralizedNode(const std::string& id, bool isSP) override;

	//DecentEnclave methods:
	virtual std::string GetDecentSelfRAReport() const override;
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) override;
	virtual bool ToDecentNode(const std::string& nodeID, bool isServer) override;
	virtual bool ProcessDecentTrustedMsg(const std::string& nodeID, const std::unique_ptr<Connection>& connection, const std::string& jsonMsg) override;
	virtual bool SendProtocolKey(const std::string& nodeID, const std::unique_ptr<Connection>& connection) override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;

protected:
	virtual std::string GenerateDecentSelfRAReport() override;

private:
	std::string m_selfRaReport;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
