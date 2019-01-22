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
			DecentralizedEnclave(const sgx_spid_t& spid, const std::shared_ptr<Ias::Connector>& iasConnector, const std::string& enclavePath, const Decent::Tools::KnownFolderType tokenLocType, const std::string& tokenFileName);

			virtual ~DecentralizedEnclave();

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Net::Connection& connection) override;
		};
	}
}
