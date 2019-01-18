#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#pragma once

#include "../Decent/DecentServer.h"
#include "../SGX/EnclaveServiceProvider.h"

typedef struct _spid_t sgx_spid_t;

namespace DecentSgx
{
	class DecentServer : public Sgx::EnclaveServiceProvider, virtual public Decent::DecentServer
	{
	public:
		DecentServer(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const std::string& tokenPath);
		DecentServer(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const fs::path& enclavePath, const fs::path& tokenPath);
		DecentServer(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName);

		virtual ~DecentServer();

		//DecentEnclave methods:
		virtual std::string GetDecentSelfRAReport() const override;
		virtual void LoadConstWhiteList(const std::string& key, const std::string& whiteList) override;
		virtual void ProcessAppCertReq(const std::string& wListKey, Connection& connection) override;

		virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

	protected:
		virtual std::string GenerateDecentSelfRAReport() override;

	private:
		std::string m_selfRaReport;
	};
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
