#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#pragma once

#include "EnclaveServiceProvider.h"
#include "../Base/DecentralizedEnclave.h"

#include <memory>

typedef struct _spid_t sgx_spid_t;

namespace Decent
{
	namespace Sgx
	{
		class DecentralizedEnclave : public Sgx::EnclaveServiceProvider, virtual public Base::DecentralizedEnclave
		{
		public:
			DecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& iasConnector, const std::string& enclavePath, const std::string& tokenPath);
			DecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& iasConnector, const fs::path& enclavePath, const fs::path& tokenPath);
			DecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& iasConnector, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

			virtual ~DecentralizedEnclave();

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Net::Connection& connection) override;
		};
	}
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL