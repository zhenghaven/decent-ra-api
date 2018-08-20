#pragma once

#include <cstdint>
#include <memory>
#include <string>

class Connection;
class ClientRASession;

//TODO: Replace these SGX component with general components.
#include <sgx_error.h>
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class EnclaveBase
{
public:
	virtual ~EnclaveBase();

	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) = 0;

	virtual std::shared_ptr<ClientRASession> GetRASession(std::unique_ptr<Connection>& connection) = 0;

	virtual std::shared_ptr<ClientRASession> GetRASession();

};

