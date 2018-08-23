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

	//SGXEnclave methods:
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID) override;

	//DecentEnclave methods:
	virtual std::string GetDecentSelfRAReport() const override;
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) override;
	virtual bool ProcessDecentTrustedMsg(const std::string& nodeID, const std::unique_ptr<Connection>& connection, const std::string& jsonMsg) override;

	virtual bool ToDecentralizedNode(const std::string& id, bool isSP) override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;

protected:
	virtual std::string GenerateDecentSelfRAReport() override;

private:
	std::string m_selfRaReport;
};
