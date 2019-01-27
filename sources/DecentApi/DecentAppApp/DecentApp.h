#pragma once

#include "../CommonApp/Ra/DecentApp.h"
#include "../CommonApp/SGX/EnclaveBase.h"

#include <memory>

namespace Decent
{
	namespace Net
	{
		class Connection;
	}

	namespace RaSgx
	{
		class DecentApp : public Sgx::EnclaveBase, virtual public Ra::DecentApp
		{
		public:
			DecentApp() = delete;
			DecentApp(const std::string& enclavePath, const std::string& tokenPath, const std::string& wListKey, Net::Connection& serverConn);
			DecentApp(const fs::path& enclavePath, const fs::path& tokenPath, const std::string& wListKey, Net::Connection& serverConn);
			DecentApp(const std::string& enclavePath, const Decent::Tools::KnownFolderType tokenLocType, const std::string& tokenFileName, const std::string& wListKey, Net::Connection& serverConn);

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
