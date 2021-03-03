#pragma once

#include "../CommonApp/Ra/DecentApp.h"
#include "../CommonApp/SGX/EnclaveBase.h"

#include <memory>

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;
	}

	namespace RaSgx
	{
		class DecentApp : public Sgx::EnclaveBase, virtual public Ra::DecentApp
		{
		public:
			DecentApp() = delete;

			DecentApp(const std::string& enclavePath, const std::string& tokenPath, const std::string& wListKey, Net::ConnectionBase& serverConn);

			DecentApp(const fs::path& enclavePath, const fs::path& tokenPath, const std::string& wListKey, Net::ConnectionBase& serverConn);

			DecentApp(const std::string& enclavePath, const std::string& tokenPath,
				const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep,
				const std::string& wListKey, Net::ConnectionBase& serverConn);

			DecentApp(const fs::path& enclavePath, const fs::path& tokenPath,
				const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep,
				const std::string& wListKey, Net::ConnectionBase& serverConn);

			virtual ~DecentApp();

			virtual std::string GetAppX509Cert() override;

			virtual bool ProcessSmartMessage(const std::string& category, Net::ConnectionBase& connection, Net::ConnectionBase*& freeHeldCnt) override;

		private:
			bool InitEnclave(const std::string& wListKey, Net::ConnectionBase& serverConn);

			std::string m_appCert;
		};
	}
}
