#pragma once

#include "ServiceProviderBase.h"

#include <memory>

namespace Decent
{
	namespace Ias
	{
		class Connector;
	}

	namespace Sgx
	{
		class ServiceProvider : virtual public Sgx::ServiceProviderBase
		{
		public:
			ServiceProvider() = delete;

			ServiceProvider(const std::shared_ptr<Ias::Connector>& ias);

			virtual ~ServiceProvider();

			virtual void GetSpPublicSignKey(general_secp256r1_public_t& outKey) const override;

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Net::Connection& connection) override;

		protected:
			std::shared_ptr<const Ias::Connector> m_ias;
		};
	}
}
