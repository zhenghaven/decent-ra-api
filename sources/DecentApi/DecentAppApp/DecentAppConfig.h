#pragma once

#include "../CommonApp/AppConfig/EnclaveList.h"

namespace Decent
{
	namespace AppConfig
	{
		class DecentAppConfig
		{
		public:
			DecentAppConfig() = delete;

			DecentAppConfig(const std::string& jsonStr);

			DecentAppConfig(const Json::Value& json);

			virtual ~DecentAppConfig();

			const AppConfig::EnclaveList& GetEnclaveList() const { return m_enclaveList; }

		private:
			EnclaveList m_enclaveList;
		};
	}
}
