#pragma once

#include <memory>

#include "Networking/ConnectionHandler.h"

class Connection;
class ServiceProviderRASession;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class ServiceProviderBase : virtual public ConnectionHandler
{
public:
	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession(std::unique_ptr<Connection>& connection) = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession();

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) override;
};
