#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#pragma once

#include "../Decent/DecentApp.h"
#include "../SGX/EnclaveBase.h"

#include <memory>

class Connection;

namespace DecentSgx
{
	class DecentApp : public Sgx::EnclaveBase, virtual public Decent::DecentApp
	{
	public:
		DecentApp() = delete;
		DecentApp(const std::string& enclavePath, const std::string& tokenPath, const std::string& wListKey, Connection& serverConn);
		DecentApp(const fs::path& enclavePath, const fs::path& tokenPath, const std::string& wListKey, Connection& serverConn);
		DecentApp(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName, const std::string& wListKey, Connection& serverConn);

		virtual ~DecentApp();

		virtual bool GetX509FromServer(const std::string& decentId, Connection& connection) override;

		virtual const std::string& GetAppCert() const override;

		virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

	private:
		bool InitEnclave(const std::string& wListKey, Connection& serverConn);

		std::string m_appCert;
	};
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
