#pragma once

#include "EnclaveBase.h"

#include <string>

#include <sgx_eid.h>

#include "FileSystemUtil.h"
#include "EnclaveUtil.h"

class SGXEnclave : public EnclaveBase
{
public:
	SGXEnclave() = delete;
	SGXEnclave(const std::string enclavePath, const std::string tokenPath);
	SGXEnclave(const std::string enclavePath, const fs::path tokenPath);
	SGXEnclave(const std::string enclavePath, const KnownFolderType tokenLocType, const std::string tokenFileName);

	virtual bool Launch() override;
	virtual bool IsLastExecutionFailed() const override;
	virtual bool IsLaunched() const override;

	sgx_status_t GetLastStatus() const;

	~SGXEnclave();

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
};