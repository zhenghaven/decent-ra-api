#include "SGXRemoteAttestationServer.h"

#include "SGXRemoteAttestationSession.h"

SGXRemoteAttestationServer::SGXRemoteAttestationServer(uint32_t ipAddr, uint16_t portNum) :
	RemoteAttestationServer(ipAddr, portNum)
{
}

SGXRemoteAttestationServer::~SGXRemoteAttestationServer()
{
}

RemoteAttestationSession * SGXRemoteAttestationServer::AcceptRAConnection()
{
	RemoteAttestationSession* session = new SGXRemoteAttestationSession(*m_RAServerAcc);
	return session;
}
