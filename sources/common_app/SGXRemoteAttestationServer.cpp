#include "SGXRemoteAttestationServer.h"

#include "Networking/Connection.h"

SGXRemoteAttestationServer::SGXRemoteAttestationServer(uint32_t ipAddr, uint16_t portNum) :
	RemoteAttestationServer(ipAddr, portNum)
{
}

SGXRemoteAttestationServer::~SGXRemoteAttestationServer()
{
}

std::unique_ptr<Connection> SGXRemoteAttestationServer::AcceptRAConnection(size_t bufferSize)
{
	std::unique_ptr<Connection> connection(std::make_unique<Connection>(m_RAServerIO, *m_RAServerAcc, bufferSize));
	return std::move(connection);
}
