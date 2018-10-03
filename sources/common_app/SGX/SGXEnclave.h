#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "../EnclaveBase.h"

#include <string>
#include <vector>
#include <cstdint>

#include <sgx_error.h>

#include "../FileSystemDefs.h"

namespace boost
{
	namespace filesystem
	{
		class path;
	}
}
namespace fs = boost::filesystem;

class Server;

typedef uint32_t sgx_ra_context_t;
typedef uint64_t sgx_enclave_id_t;

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;

typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;

typedef struct _ias_report_t sgx_ias_report_t;

typedef struct _sgx_dh_msg1_t sgx_dh_msg1_t;
typedef struct _sgx_dh_msg2_t sgx_dh_msg2_t;
typedef struct _sgx_dh_msg3_t sgx_dh_msg3_t;

typedef struct _quote_nonce sgx_quote_nonce_t;
typedef struct _target_info_t sgx_target_info_t;
typedef struct _report_t sgx_report_t;

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
	static constexpr char const sk_platformType[] = "SGX";

public:
	SGXEnclave() = delete;
	SGXEnclave(const std::string& enclavePath, const std::string& tokenPath);
	SGXEnclave(const fs::path& enclavePath, const fs::path& tokenPath);
	SGXEnclave(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	virtual ~SGXEnclave();

	virtual const char* GetPlatformType() const override;
	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) const override;
	virtual const std::string GetRAClientSignPubKey() const override;
	virtual ClientRASession* GetRAClientSession(Connection& connection) override;

	virtual uint32_t GetExGroupID();

	//***************************************
	//  Remote Attestation Methods
	//***************************************

	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1);
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID);
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID, sgx_ecall_proc_msg2_trusted_t proc_msg2_func, sgx_ecall_get_msg3_trusted_t get_msg3_func);
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ias_report_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

protected:
	const sgx_enclave_id_t GetEnclaveId() const;
	static bool LoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken);
	static bool UpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken);
	static sgx_enclave_id_t LaunchEnclave(const fs::path& enclavePath, const fs::path& tokenPath);

private:
	const sgx_enclave_id_t m_eid;
	const std::string m_enclavePath;
	//const fs::path m_tokenPath;

};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
