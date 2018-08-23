#pragma once

#include "../EnclaveBase.h"

#include <string>

#include <sgx_eid.h>
#include <sgx_tcrypto.h>

#include "../FileSystemUtil.h"
#include "../EnclaveUtil.h"
#include "IAS/IASConnector.h"

class Server;
typedef uint32_t sgx_ra_context_t;
typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;
typedef struct _ra_msg4_t sgx_ra_msg4_t;

typedef sgx_status_t(*sgx_ecall_proc_msg2_trusted_t)(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	sgx_ra_context_t context,
	const sgx_ra_msg2_t *p_msg2,
	const sgx_target_info_t *p_qe_target,
	sgx_report_t *p_report,
	sgx_quote_nonce_t* nonce);

typedef sgx_status_t(*sgx_ecall_get_msg3_trusted_t)(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	sgx_ra_context_t context,
	uint32_t quote_size,
	sgx_report_t* qe_report,
	sgx_ra_msg3_t *p_msg3,
	uint32_t msg3_size);

class SGXEnclave : virtual public EnclaveBase
{
public:
	SGXEnclave() = delete;
	SGXEnclave(const std::string& enclavePath, const std::string& tokenPath);
	SGXEnclave(const fs::path& enclavePath, const fs::path& tokenPath);
	SGXEnclave(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	virtual ~SGXEnclave();

	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) const override;
	virtual std::shared_ptr<ClientRASession> GetRAClientSession(std::unique_ptr<Connection>& connection) override;

	virtual uint32_t GetExGroupID();

	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1);
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID);
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID, sgx_ecall_proc_msg2_trusted_t proc_msg2_func, sgx_ecall_get_msg3_trusted_t get_msg3_func);
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ra_msg4_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, sgx_ra_context_t inContextID);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;

protected:
	const sgx_enclave_id_t GetEnclaveId() const;
	static bool LoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken);
	static bool UpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken);
	static sgx_enclave_id_t LaunchEnclave(const fs::path& enclavePath, const fs::path& tokenPath);

private:
	const sgx_enclave_id_t m_eid;
	const fs::path m_enclavePath;
	const fs::path m_tokenPath;

};