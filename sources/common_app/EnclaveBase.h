#pragma once

#include <cstdint>
#include <memory>

class Connection;

//TODO: Replace these SGX component with general components.
#include <sgx_error.h>
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;

class EnclaveBase
{
public:
	EnclaveBase();
	~EnclaveBase();

	virtual bool Launch() = 0;

	virtual bool IsLastExecutionFailed() const = 0;

	virtual bool IsLaunched() const = 0;

	virtual std::unique_ptr<Connection> RequestRA(uint32_t ipAddr, uint16_t portNum) = 0;

	virtual void LaunchRAServer(uint32_t ipAddr, uint16_t portNum) = 0;

	virtual bool IsRAServerLaunched() const = 0;

	virtual std::unique_ptr<Connection> AcceptRAConnection() = 0;

	virtual std::string GetRASenderID() const = 0;

	virtual sgx_status_t GetRASignPubKey(sgx_ec256_public_t& outKey) = 0;

	virtual sgx_status_t GetRAEncrPubKey(sgx_ec256_public_t& outKey) = 0;
};

