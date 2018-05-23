#pragma once

#include "RemoteAttestationServer.h"

class SGXRemoteAttestationServer : public RemoteAttestationServer
{
public:
	SGXRemoteAttestationServer() = delete;
	SGXRemoteAttestationServer(uint32_t ipAddr, uint16_t portNum);
	~SGXRemoteAttestationServer();

	virtual RemoteAttestationSession* AcceptRAConnection() override;

private:

};
