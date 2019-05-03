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
		public: //static member:
			static constexpr char const sk_platformType[] = "SGX";
			static bool InternalLoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken);
			static bool InternalUpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken);
			static void InternalInitSgxEnclave(const sgx_enclave_id_t& encId);

		public:
			EnclaveBase() = delete;

			EnclaveBase(const std::string& enclavePath, const std::string& tokenPath, 
				const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep);

			EnclaveBase(const fs::path& enclavePath, const fs::path& tokenPath,
				const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep);

			EnclaveBase(const std::string& enclavePath, const std::string& tokenPath);

			EnclaveBase(const fs::path& enclavePath, const fs::path& tokenPath);

			virtual ~EnclaveBase();

			virtual const char* GetPlatformType() const override;

			virtual uint32_t GetExGroupID();

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Net::Connection& connection) override;

		protected:
			const sgx_enclave_id_t GetEnclaveId() const;

		private:
			const sgx_enclave_id_t m_eid;
			const std::string m_enclavePath;

		};
	}
}
