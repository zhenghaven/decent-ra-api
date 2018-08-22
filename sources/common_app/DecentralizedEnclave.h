#pragma once

#include <string>

#include <sgx_error.h>

//#include "EnclaveBase.h"
//#include "ServiceProviderBase.h"
#include "Networking/ConnectionHandler.h"

class DecentralizedEnclave : virtual public ConnectionHandler
{
public:
	virtual sgx_status_t TransitToDecentNode(const std::string& id, bool isSP) = 0;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;
};
