#pragma once

#include "RemoteAttestationServer.h"

class SGXRemoteAttestationServer : public RemoteAttestationServer
{
public:
	SGXRemoteAttestationServer() = delete;
	SGXRemoteAttestationServer(uint32_t ipAddr, uint16_t portNum);
	~SGXRemoteAttestationServer();

	virtual std::unique_ptr<Connection> AcceptRAConnection(size_t bufferSize = 5000U) override;

private:

};
