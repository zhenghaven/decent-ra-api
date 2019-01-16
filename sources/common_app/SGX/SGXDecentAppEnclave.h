#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#pragma once

#include "../DecentAppEnclave.h"
#include "SGXEnclave.h"

#include <memory>

class Connection;

class SGXDecentAppEnclave : public SGXEnclave, virtual public DecentAppEnclave
{
public:
	SGXDecentAppEnclave() = delete;
	SGXDecentAppEnclave(const std::string& enclavePath, const std::string& tokenPath, const std::string& wListKey, Connection& serverConn);
	SGXDecentAppEnclave(const fs::path& enclavePath, const fs::path& tokenPath, const std::string& wListKey, Connection& serverConn);
	SGXDecentAppEnclave(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName, const std::string& wListKey, Connection& serverConn);
	
	virtual ~SGXDecentAppEnclave();

	//virtual bool ProcessDecentSelfRAReport(std::string& inReport) override;
	//virtual bool ProcessDecentSelfRAReport(const std::string& inReport) override;

	virtual bool GetX509FromServer(const std::string& decentId, Connection& connection) override;

	virtual const std::string& GetAppCert() const override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

private:
	bool InitEnclave(const std::string& wListKey, Connection& serverConn);

	std::string m_appCert;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
