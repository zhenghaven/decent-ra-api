#pragma once

#include "EnclaveBase.h"

#include <string>

#include <sgx_eid.h>

#include "FileSystemUtil.h"
#include "EnclaveUtil.h"

class SGXRemoteAttestationServer;

class SGXEnclave : public EnclaveBase
{
public:
	SGXEnclave() = delete;
	SGXEnclave(const std::string enclavePath, const std::string tokenPath);
	SGXEnclave(const std::string enclavePath, const fs::path tokenPath);
	SGXEnclave(const std::string enclavePath, const KnownFolderType tokenLocType, const std::string tokenFileName);

	~SGXEnclave();

	virtual bool Launch() override;
	virtual bool IsLastExecutionFailed() const override;
	virtual bool IsLaunched() const override;
	virtual bool RequestRA(uint32_t ipAddr, uint16_t portNum) override;

	//Decent enclave functions:
	virtual void LaunchRAServer(uint32_t ipAddr, uint16_t port) override;
	virtual bool IsRAServerLaunched() const override;
	virtual bool AcceptRAConnection() override;

	sgx_status_t GetLastStatus() const;

protected:
	sgx_enclave_id_t GetEnclaveId() const;
	bool LoadToken();
	bool UpdateToken();

private:
	sgx_enclave_id_t m_eid;
	sgx_status_t m_lastStatus;
	std::vector<uint8_t> m_token;

	const std::string m_enclavePath;
	const fs::path m_tokenPath;

	SGXRemoteAttestationServer* m_raServer;
};