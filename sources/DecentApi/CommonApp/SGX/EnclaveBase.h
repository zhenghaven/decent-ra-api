#pragma once

#include "../Base/EnclaveBase.h"

#include <string>
#include <vector>
#include <cstdint>

#include "../Tools/FileSystemDefs.h"

namespace boost
{
	namespace filesystem
	{
		class path;
	}
}
namespace fs = boost::filesystem;

typedef uint64_t sgx_enclave_id_t;

namespace Decent
{
	namespace Sgx
	{
		class EnclaveBase : virtual public Base::EnclaveBase
		{
		public:
			static constexpr char const sk_platformType[] = "SGX";

		public:
			EnclaveBase() = delete;
			EnclaveBase(const std::string& enclavePath, const std::string& tokenPath);
			EnclaveBase(const fs::path& enclavePath, const fs::path& tokenPath);
			EnclaveBase(const std::string& enclavePath, const Decent::Tools::KnownFolderType tokenLocType, const std::string& tokenFileName);

			virtual ~EnclaveBase();

			virtual const char* GetPlatformType() const override;

			virtual uint32_t GetExGroupID();

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Net::Connection& connection) override;

		protected:
			const sgx_enclave_id_t GetEnclaveId() const;
			static bool LoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken);
			static bool UpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken);
			static sgx_enclave_id_t LaunchEnclave(const fs::path& enclavePath, const fs::path& tokenPath);

		private:
			const sgx_enclave_id_t m_eid;
			const std::string m_enclavePath;

		};
	}
}