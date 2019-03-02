#pragma once

#include "../CommonApp/Tools/ConfigManager.h"

typedef struct _spid_t sgx_spid_t;

namespace Decent
{
	namespace Tools
	{
		class ServerConfigManager : public ConfigManager
		{
		public: //Static members:
			static constexpr char const sk_labelSpCertPath[] = "SpCertPath";
			static constexpr char const sk_labelSpPrvKeyPath[] = "SpPrvKeyPath";
			static constexpr char const sk_labelSpid[] = "IasSpid";

		public:
			ServerConfigManager() = delete;

			ServerConfigManager(const std::string& jsonStr);

			ServerConfigManager(const Json::Value& json);

			virtual ~ServerConfigManager();

			const sgx_spid_t& GetSpid() const { return *m_spid; }
			const std::string& GetServiceProviderCertPath() const { return m_spCertPath; }
			const std::string& GetServiceProviderPrvKeyPath() const { return m_spPrvKeyPath; }

		protected:
			ServerConfigManager(const Json::Value& root, const Json::Value& server);

		private:
			std::unique_ptr<sgx_spid_t> m_spid;
			std::string m_spCertPath;
			std::string m_spPrvKeyPath;
		};
	}
}
