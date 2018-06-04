#include "RemoteAttestationSession.h"

#include "Networking/Connection.h"

RemoteAttestationSession::RemoteAttestationSession(std::unique_ptr<Connection>& m_connection, RemoteAttestationSession::Mode mode) :
	m_connection(std::move(m_connection)),
	m_mode(mode)
{
}

RemoteAttestationSession::~RemoteAttestationSession()
{
}

std::unique_ptr<Connection>&& RemoteAttestationSession::ReleaseConnection()
{
	return std::move(m_connection);
}

void RemoteAttestationSession::AssignConnection(std::unique_ptr<Connection>& inConnection)
{
	m_connection.reset();
	m_connection.swap(inConnection);
}

void RemoteAttestationSession::SwapConnection(std::unique_ptr<Connection>& inConnection)
{
	m_connection.swap(inConnection);
}

RemoteAttestationSession::Mode RemoteAttestationSession::GetMode() const
{
	return m_mode;
}
