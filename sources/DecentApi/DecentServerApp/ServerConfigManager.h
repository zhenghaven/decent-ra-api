#pragma once

#include "../CommonApp/Tools/ConfigManager.h"

namespace Decent
{
	namespace Tools
	{
		class ServerConfigManager : public ConfigManager
		{
		public: //Static members:
			static constexpr char const sk_labelSpCertPath[] = "SpCertPath";
			static constexpr char const sk_labelSpPrvKeyPath[] = "SpPrvKeyPath";

		public:
			ServerConfigManager() = delete;

			ServerConfigManager(const std::string& jsonStr);

			ServerConfigManager(const Json::Value& json);

			virtual ~ServerConfigManager();

			const std::string& GetServiceProviderCertPath() const { return m_spCertPath; }
			const std::string& GetServiceProviderPrvKeyPath() const { return m_spPrvKeyPath; }

		private:
			std::string m_spCertPath;
			std::string m_spPrvKeyPath;
		};
	}
}
