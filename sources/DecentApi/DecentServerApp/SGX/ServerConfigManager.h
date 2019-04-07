#pragma once

#include "../ServerConfigManager.h"

typedef struct _spid_t sgx_spid_t;

namespace Decent
{
	namespace Sgx
	{
		class ServerConfigManager : public Tools::ServerConfigManager
		{
		public: //Static members:
			static constexpr char const sk_labelSpid[] = "IasSpid";

		public:
			ServerConfigManager() = delete;

			ServerConfigManager(const std::string& jsonStr);

			ServerConfigManager(const Json::Value& json);

			virtual ~ServerConfigManager();

			const sgx_spid_t& GetSpid() const { return *m_spid; }

		private:
			std::unique_ptr<sgx_spid_t> m_spid;
		};
	}
}
