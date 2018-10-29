#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#pragma once

#include "SGXServiceProviderBase.h"

#include <memory>

class IASConnector;

class SGXServiceProvider : virtual public SGXServiceProviderBase
{
public:
	SGXServiceProvider() = delete;

	SGXServiceProvider(const std::shared_ptr<IASConnector>& ias);

	virtual ~SGXServiceProvider(); 

	virtual void GetSpPublicSignKey(general_secp256r1_public_t& outKey) const override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

protected:
	std::shared_ptr<const IASConnector> m_ias;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
