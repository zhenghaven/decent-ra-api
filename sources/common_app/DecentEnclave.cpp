#include "DecentEnclave.h"

#include "Common.h"

#include "SGXRemoteAttestationServer.h"
#include "SGXRemoteAttestationSession.h"
#include "DecentSGXRASession.h"

#include "Networking/Connection.h"

DecentEnclave::~DecentEnclave()
{

}

std::unique_ptr<Connection> DecentEnclave::AcceptRAConnection()
{
	DecentNodeMode nodeMode = GetDecentMode();
	switch (nodeMode)
	{
	case DecentNodeMode::ROOT_SERVER:
		return AcceptRootNodeRAConnection();
		//break;
	case DecentNodeMode::APPL_SERVER:
	default:
		return AcceptAppNodeConnection();
		break;
	}
}

std::unique_ptr<Connection> DecentEnclave::RequestRA(uint32_t ipAddr, uint16_t portNum)
{
	return RequestRootNodeRA(ipAddr, portNum);
}

std::unique_ptr<Connection> DecentEnclave::RequestAppNodeConnection(uint32_t ipAddr, uint16_t portNum)
{
	bool res = true;

	std::unique_ptr<Connection> connection(std::make_unique<Connection>(ipAddr, portNum));

	DecentSGXRASession decentSession(connection, RemoteAttestationSession::Mode::Client);

	res = decentSession.ProcessClientMessage0(*this);
	if (!res)
	{
		return nullptr;
	}

	return res ? decentSession.ReleaseConnection() : nullptr;
}

std::unique_ptr<Connection> DecentEnclave::RequestRootNodeRA(uint32_t ipAddr, uint16_t portNum)
{
	bool res = true;

	std::unique_ptr<Connection> connection(std::make_unique<Connection>(ipAddr, portNum));
	SGXRemoteAttestationSession RASession(connection, RemoteAttestationSession::Mode::Client);
	//Client attests to Server.
	res = RASession.ProcessClientSideRA(*this);
	if (!res)
	{
		return nullptr;
	}
	//Swap connection.
	RASession.SwapConnection(connection);
	DecentSGXRASession decentSession(connection, RemoteAttestationSession::Mode::Client);
	//Try to reverse the RA direction.
	res = decentSession.SendReverseRARequest(GetRASenderID());
	if (!res)
	{
		return nullptr;
	}
	//Swap connection.
	decentSession.SwapConnection(connection);
	RASession.SwapConnection(connection);
	//Server attests to Client.
	res = RASession.ProcessServerSideRA(*this);
	if (!res)
	{
		return nullptr;
	}
	//Swap connection.
	RASession.SwapConnection(connection);
	decentSession.SwapConnection(connection);
	//Try to reverse the message direction.
	res = decentSession.RecvReverseRARequest();
	if (!res)
	{
		return nullptr;
	}
	//Send key request to server.
	res = decentSession.ProcessClientSideKeyRequest(*this);
	if (!res)
	{
		return nullptr;
	}

	return res ? decentSession.ReleaseConnection() : nullptr;
}

std::unique_ptr<Connection> DecentEnclave::AcceptAppNodeConnection()
{
	bool res = true;

	std::unique_ptr<Connection> connection(m_raServer->AcceptRAConnection());

	DecentSGXRASession decentSession(connection, RemoteAttestationSession::Mode::Server);

	res = decentSession.ProcessServerMessage0(*this);
	if (!res)
	{
		return nullptr;
	}

	return res ? decentSession.ReleaseConnection() : nullptr;
}

std::unique_ptr<Connection> DecentEnclave::AcceptRootNodeRAConnection()
{
	bool res = true;

	std::unique_ptr<Connection> connection(m_raServer->AcceptRAConnection());
	SGXRemoteAttestationSession RASession(connection, RemoteAttestationSession::Mode::Server);
	//Client attests to Server.
	res = RASession.ProcessServerSideRA(*this);
	if (!res)
	{
		return nullptr;
	}
	//Swap connection.
	RASession.SwapConnection(connection);
	DecentSGXRASession decentSession(connection, RemoteAttestationSession::Mode::Server);
	//Try to reverse the RA direction.
	res = decentSession.RecvReverseRARequest();
	if (!res)
	{
		return nullptr;
	}
	//Swap connection.
	decentSession.SwapConnection(connection);
	RASession.SwapConnection(connection);
	//Server attests to Client.
	res = RASession.ProcessClientSideRA(*this);
	if (!res)
	{
		return nullptr;
	}
	//Swap connection.
	RASession.SwapConnection(connection);
	decentSession.SwapConnection(connection);
	//Try to reverse the message direction.
	res = decentSession.SendReverseRARequest(GetRASenderID());
	if (!res)
	{
		return nullptr;
	}
	//Process client's key request.
	res = decentSession.ProcessServerSideKeyRequest(*this);
	if (!res)
	{
		return nullptr;
	}

	return res ? decentSession.ReleaseConnection() : nullptr;
}
