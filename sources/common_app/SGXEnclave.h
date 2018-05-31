#pragma once

#include "EnclaveBase.h"

#include <string>

#include <sgx_eid.h>
#include <sgx_tcrypto.h>

#include "FileSystemUtil.h"
#include "EnclaveUtil.h"

class SGXRemoteAttestationServer;
typedef uint32_t sgx_ra_context_t;
struct _ra_msg1_t;
typedef _ra_msg1_t sgx_ra_msg1_t;

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
	virtual sgx_status_t GetRAPublicKey(sgx_ec256_public_t& outKey) = 0;
	virtual sgx_status_t SetSrvPrvRAPublicKey(sgx_ec256_public_t& outKey) = 0;
	virtual sgx_status_t EnclaveInitRA(int enablePSE, sgx_ra_context_t& outContextID) = 0;
	virtual sgx_status_t GetRAMsg1(sgx_ra_msg1_t& outMsg1, sgx_ra_context_t& inContextID) = 0; //This has to be abstract. (B.C. a function is from edger)

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