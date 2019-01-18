#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENTRALIZED_ENCLAVE_INTERNAL || USE_DECENT_ENCLAVE_SERVER_INTERNAL)

#include "EnclaveBase.h"
#include "ServiceProviderBase.h"
#include "../EnclaveServiceProviderBase.h"

#include <memory>

class IASConnector;

namespace Sgx
{
	class EnclaveServiceProvider : public Sgx::EnclaveBase, virtual public Sgx::ServiceProviderBase, virtual public EnclaveServiceProviderBase
	{
	public:
		EnclaveServiceProvider() = delete;

		EnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const std::string& tokenPath);
		EnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const fs::path& enclavePath, const fs::path& tokenPath);
		EnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

		virtual ~EnclaveServiceProvider();

		virtual const char* GetPlatformType() const override;

		virtual void GetSpPublicSignKey(general_secp256r1_public_t& outKey) const override;

		virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

	protected:
		std::shared_ptr<const IASConnector> m_ias;
	};
}


#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENTRALIZED_ENCLAVE_INTERNAL || USE_DECENT_ENCLAVE_SERVER_INTERNAL)
