#pragma once

#include <memory>
#include <string>

#include "../../Common/Tools/JsonForwardDeclare.h"

typedef struct _spid_t sgx_spid_t;

namespace Decent
{
	namespace AppConfig
	{
		class SgxServiceProvider
		{
		public: //Static members:
			static constexpr char const sk_defaultLabel[] = "SgxServiceProvider";

			static constexpr char const sk_labelSpid[] = "IasSpid";
			static constexpr char const sk_labelSubscriptionKey[] = "SubscriptionKey";

		public:
			
			SgxServiceProvider(const Tools::JsonValue& json);

			virtual ~SgxServiceProvider();

			const sgx_spid_t& GetSpid() const { return *m_spid; }

			const std::string& GetSubscriptionKey() const { return m_subsriptionKey; }

		private:
			std::unique_ptr<sgx_spid_t> m_spid;
			std::string m_subsriptionKey;
		};
	}
}
