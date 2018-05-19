#pragma once

#include <cstdint>

class RemoteAttestationSession;

class EnclaveBase
{
public:
	EnclaveBase();
	~EnclaveBase();

	virtual bool Launch() = 0;

	virtual bool IsLastExecutionFailed() const = 0;

	virtual bool IsLaunched() const = 0;

	virtual void LaunchRemoteAttestationServer(uint32_t ipAddr, short port) = 0;

	virtual bool IsRAServerLaunched() const = 0;

	virtual RemoteAttestationSession* AcceptRAConnection() = 0;
};

