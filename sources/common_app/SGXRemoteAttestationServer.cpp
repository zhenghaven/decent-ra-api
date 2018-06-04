#include "SGXRemoteAttestationServer.h"

#include "SGXRemoteAttestationSession.h"
#include "Networking/Connection.h"

SGXRemoteAttestationServer::SGXRemoteAttestationServer(uint32_t ipAddr, uint16_t portNum) :
	RemoteAttestationServer(ipAddr, portNum)
{
}

SGXRemoteAttestationServer::~SGXRemoteAttestationServer()
{
}

RemoteAttestationSession * SGXRemoteAttestationServer::AcceptRAConnection(size_t bufferSize)
{
	std::unique_ptr<Connection> connection(std::make_unique<Connection>(m_RAServerIO, *m_RAServerAcc, bufferSize));
	RemoteAttestationSession* session = new SGXRemoteAttestationSession(connection, RemoteAttestationSession::Mode::Server);
	return session;
}
