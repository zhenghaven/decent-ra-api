#pragma once

#include "../../CommonApp/AppConfig/EnclaveList.h"
#include "../../CommonApp/AppConfig/SgxServiceProvider.h"

namespace Decent
{
	namespace Sgx
	{
		class DecentServerConfig
		{
		public: //static members:
			static constexpr char const sk_labelDecentServerEnclave[] = "DecentServer";

		public:
			DecentServerConfig() = delete;

			DecentServerConfig(const std::string& jsonStr);

			DecentServerConfig(const Json::Value& json);

			virtual ~DecentServerConfig();

			const AppConfig::EnclaveListItem& GetDecentServerConfig() const { return m_decentSvr; }

			const AppConfig::SgxServiceProvider& GetSgxServiceProviderConfig() const { return m_svcProv; }

		private:
			AppConfig::EnclaveListItem m_decentSvr;
			AppConfig::SgxServiceProvider m_svcProv;
		};
	}
}
