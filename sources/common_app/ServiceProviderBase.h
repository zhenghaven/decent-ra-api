#pragma once

#include <memory>
#include <string>

#include "Networking/ConnectionHandler.h"

class Connection;
class ServiceProviderRASession;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class ServiceProviderBase : virtual public ConnectionHandler
{
public:
	virtual ~ServiceProviderBase() {}

	virtual const char* GetPlatformType() const = 0;

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) const = 0;

	virtual const std::string GetRASPSignPubKey() const = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASPSession(std::unique_ptr<Connection>& connection) = 0;
};
