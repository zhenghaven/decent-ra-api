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

typedef uint64_t sgx_enclave_id_t;

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

	virtual uint32_t GetExGroupID();

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

protected:
	const sgx_enclave_id_t GetEnclaveId() const;
	static bool LoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken);
	static bool UpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken);
	static sgx_enclave_id_t LaunchEnclave(const fs::path& enclavePath, const fs::path& tokenPath);

private:
	const sgx_enclave_id_t m_eid;
	const std::string m_enclavePath;

};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
