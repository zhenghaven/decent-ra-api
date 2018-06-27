#include "RemoteAttestationSession.h"

#include "Networking/Connection.h"
#include "EnclaveBase.h"

RemoteAttestationSession::RemoteAttestationSession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase) :
	m_connection(std::move(connection)),
	m_enclaveBase(enclaveBase)
{
}

RemoteAttestationSession::~RemoteAttestationSession()
{
}

std::string RemoteAttestationSession::GetSenderID() const
{
	return m_enclaveBase.GetRASenderID();
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
