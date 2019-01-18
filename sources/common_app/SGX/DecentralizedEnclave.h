#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#pragma once

#include "../DecentralizedEnclave.h"
#include "SGXEnclaveServiceProvider.h"

#include <memory>

typedef struct _spid_t sgx_spid_t;

class SGXDecentralizedEnclave : public SGXEnclaveServiceProvider, virtual public DecentralizedEnclave
{
public:
	SGXDecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& iasConnector, const std::string& enclavePath, const std::string& tokenPath);
	SGXDecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& iasConnector, const fs::path& enclavePath, const fs::path& tokenPath);
	SGXDecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& iasConnector, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	virtual ~SGXDecentralizedEnclave();

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL