#pragma once

#include <memory>
#include <string>

#include <sgx_status.h>

class Connection;
class ServiceProviderRASession;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class ServiceProviderBase
{
public:
	virtual ~ServiceProviderBase();

	//virtual std::string GetRASenderID() const = 0;

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) = 0;

	virtual sgx_status_t GetRASPEncrPubKey(sgx_ec256_public_t& outKey) = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession(std::unique_ptr<Connection>& connection) = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession();

};
