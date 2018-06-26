#include "DecentralizedRASession.h"

DecentralizedRASession::DecentralizedRASession(std::unique_ptr<Connection>& connection, std::shared_ptr<RemoteAttestationSession>& hardwareSession) :
	m_connection(std::move(connection)),
	m_hardwareSession(hardwareSession)
{
}

DecentralizedRASession::~DecentralizedRASession()
{
}

void DecentralizedRASession::AssignConnection(std::unique_ptr<Connection>& inConnection)
{
	m_connection.reset();
	m_connection.swap(inConnection);
}

void DecentralizedRASession::SwapConnection(std::unique_ptr<Connection>& inConnection)
{
	m_connection.swap(inConnection);
}
