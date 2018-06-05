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
struct _ra_msg2_t;
typedef _ra_msg2_t sgx_ra_msg2_t;
struct _ra_msg3_t;
typedef _ra_msg3_t sgx_ra_msg3_t;
struct _ra_msg4_t;
typedef _ra_msg4_t sgx_ra_msg4_t;

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
	virtual std::unique_ptr<Connection> RequestRA(uint32_t ipAddr, uint16_t portNum) override;

	virtual std::string GetRASenderID() const;
	virtual uint32_t GetExGroupID() const;

	virtual sgx_status_t GetRASignPubKey(sgx_ec256_public_t& outKey) = 0;
	//virtual sgx_status_t GetRAEncrPubKey(sgx_ec256_public_t& outKey) = 0;
	virtual sgx_status_t InitRAEnvironment() = 0;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) = 0;
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) = 0;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) = 0;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const sgx_ra_msg2_t& inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t& inContextID) = 0; //A decent protocol like function.
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const sgx_ra_msg3_t& inMsg3, const uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign) = 0;
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ra_msg4_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, sgx_ra_context_t inContextID) = 0;
	virtual sgx_status_t TerminationClean() = 0;

	//Decent enclave functions:
	virtual void LaunchRAServer(uint32_t ipAddr, uint16_t port) override;
	virtual bool IsRAServerLaunched() const override;
	virtual std::unique_ptr<Connection> AcceptRAConnection() override;

	sgx_status_t GetLastStatus() const;

protected:
	sgx_enclave_id_t GetEnclaveId() const;
	bool LoadToken();
	bool UpdateToken();

	std::string m_raSenderID;
	uint32_t m_exGroupID;
	sgx_status_t m_lastStatus;

private:
	sgx_enclave_id_t m_eid;
	std::vector<uint8_t> m_token;

	const std::string m_enclavePath;
	const fs::path m_tokenPath;

	SGXRemoteAttestationServer* m_raServer;
};