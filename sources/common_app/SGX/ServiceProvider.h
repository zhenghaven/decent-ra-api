#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#pragma once

#include "ServiceProviderBase.h"

#include <memory>

class IASConnector;

namespace Sgx
{
	class ServiceProvider : virtual public Sgx::ServiceProviderBase
	{
	public:
		ServiceProvider() = delete;

		ServiceProvider(const std::shared_ptr<IASConnector>& ias);

		virtual ~ServiceProvider();

		virtual void GetSpPublicSignKey(general_secp256r1_public_t& outKey) const override;

		virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

	protected:
		std::shared_ptr<const IASConnector> m_ias;
	};
}


#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
