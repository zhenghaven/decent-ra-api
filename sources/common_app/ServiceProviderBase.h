#pragma once

#include <memory>

#include "Networking/ConnectionHandler.h"

class Connection;
class ServiceProviderRASession;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class ServiceProviderBase : virtual public ConnectionHandler
{
public:
	virtual ~ServiceProviderBase() {}

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) const = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASPSession(std::unique_ptr<Connection>& connection) = 0;
};
