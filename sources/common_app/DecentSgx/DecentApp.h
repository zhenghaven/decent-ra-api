#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#pragma once

#include "../Ra/DecentApp.h"
#include "../SGX/EnclaveBase.h"

#include <memory>

namespace Decent
{
	namespace Net
	{
		class Connection;
	}

	namespace DecentSgx
	{
		class DecentApp : public Sgx::EnclaveBase, virtual public Ra::DecentApp
		{
		public:
			DecentApp() = delete;
			DecentApp(const std::string& enclavePath, const std::string& tokenPath, const std::string& wListKey, Net::Connection& serverConn);
			DecentApp(const fs::path& enclavePath, const fs::path& tokenPath, const std::string& wListKey, Net::Connection& serverConn);
			DecentApp(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName, const std::string& wListKey, Net::Connection& serverConn);

			virtual ~DecentApp();

			virtual bool GetX509FromServer(const std::string& decentId, Net::Connection& connection) override;

			virtual const std::string& GetAppCert() const override;

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Net::Connection& connection) override;

		private:
			bool InitEnclave(const std::string& wListKey, Net::Connection& serverConn);

			std::string m_appCert;
		};
	}
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
