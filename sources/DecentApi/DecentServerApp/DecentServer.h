#pragma once

#include "../CommonApp/Ra/DecentServer.h"
#include "../CommonApp/SGX/EnclaveServiceProvider.h"

typedef struct _spid_t sgx_spid_t;

namespace Decent
{
	namespace RaSgx
	{
		class DecentServer : public Sgx::EnclaveServiceProvider, virtual public Ra::DecentServer
		{
		public:
			DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& ias, const std::string& enclavePath, const std::string& tokenPath);

			DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& ias, const fs::path& enclavePath, const fs::path& tokenPath);

			DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& ias, const std::string& enclavePath, const std::string& tokenPath,
				const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep);

			DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& ias, const fs::path& enclavePath, const fs::path& tokenPath,
				const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep);

			virtual ~DecentServer();

			//DecentEnclave methods:
			virtual std::string GetDecentSelfRAReport() const override;
			virtual void LoadConstWhiteList(const std::string& key, const std::string& whiteList) override;
			virtual void ProcessAppCertReq(const std::string& wListKey, Net::ConnectionBase& connection) override;

			virtual bool ProcessSmartMessage(const std::string& category, Net::ConnectionBase& connection, Net::ConnectionBase*& freeHeldCnt) override;

		protected:
			virtual std::string GenerateDecentSelfRAReport() override;

		private:
			std::string m_selfRaReport;
		};
	}
}
