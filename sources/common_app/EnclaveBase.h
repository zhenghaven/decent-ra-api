#pragma once

#include <cstdint>
#include <memory>

class Connection;

class EnclaveBase
{
public:
	EnclaveBase();
	~EnclaveBase();

	virtual bool Launch() = 0;

	virtual bool IsLastExecutionFailed() const = 0;

	virtual bool IsLaunched() const = 0;

	virtual std::unique_ptr<Connection>&& RequestRA(uint32_t ipAddr, uint16_t portNum) = 0;

	//Decent enclave functions:
	virtual void LaunchRAServer(uint32_t ipAddr, uint16_t portNum) = 0;
	virtual bool IsRAServerLaunched() const = 0;
	virtual std::unique_ptr<Connection>&& AcceptRAConnection() = 0;
};

