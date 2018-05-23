#pragma once

#include <cstdint>

class EnclaveBase
{
public:
	EnclaveBase();
	~EnclaveBase();

	virtual bool Launch() = 0;

	virtual bool IsLastExecutionFailed() const = 0;

	virtual bool IsLaunched() const = 0;

	//Decent enclave functions:
	virtual void LaunchRAServer(uint32_t ipAddr, uint16_t port) = 0;
	virtual bool IsRAServerLaunched() const = 0;
	virtual bool AcceptRAConnection() = 0;
};

