#pragma once

#include <memory>
#include <string>

#include "Networking/ConnectionHandler.h"

class Connection;
class ClientRASession;

//TODO: Replace these SGX component with general components.
#include <sgx_error.h>
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class EnclaveBase : virtual public ConnectionHandler
{
public:
	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) = 0;

	virtual std::shared_ptr<ClientRASession> GetRASession(std::unique_ptr<Connection>& connection) = 0;

	virtual std::shared_ptr<ClientRASession> GetRASession();

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;
};

