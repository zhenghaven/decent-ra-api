#include "DecentSGXEnclave.h"

#include "Common.h"

#include "SGXRemoteAttestationSession.h"
#include "DecentSGXRASession.h"

#include "Networking/Connection.h"

DecentSGXEnclave::~DecentSGXEnclave()
{

}

std::unique_ptr<Connection> DecentSGXEnclave::RequestRootNodeRA(uint32_t ipAddr, uint16_t portNum)
{
	bool res = true;

	std::unique_ptr<Connection> connection(RequestRA(ipAddr, portNum));

	if (!connection)
	{
		return nullptr;
	}

	DecentSGXRASession decentSession(connection, RemoteAttestationSession::Mode::Client);
	res = decentSession.SendReverseRARequest(GetRASenderID());
	if (!res)
	{
		return nullptr;
	}
	decentSession.SwapConnection(connection);

	SGXRemoteAttestationSession RASession(connection, RemoteAttestationSession::Mode::Server);

	res = RASession.ProcessServerSideRA(*this);

	return res ? RASession.ReleaseConnection() : nullptr;
}

std::unique_ptr<Connection> DecentSGXEnclave::AcceptRootNodeRAConnection()
{
	bool res = true;

	std::unique_ptr<Connection> connection(AcceptRAConnection());

	if (!connection)
	{
		return nullptr;
	}

	DecentSGXRASession decentSession(connection, RemoteAttestationSession::Mode::Server);
	res = decentSession.RecvReverseRARequest();
	if (!res)
	{
		return nullptr;
	}
	decentSession.SwapConnection(connection);

	SGXRemoteAttestationSession RASession(connection, RemoteAttestationSession::Mode::Client);

	res = RASession.ProcessClientSideRA(*this);

	return res ? RASession.ReleaseConnection() : nullptr;
}
