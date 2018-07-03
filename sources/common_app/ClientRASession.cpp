#include "ClientRASession.h"

#include "Networking/Connection.h"
#include "EnclaveBase.h"

ClientRASession::ClientRASession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase) :
	m_connection(std::move(connection)),
	m_enclaveBase(enclaveBase)
{
}

ClientRASession::~ClientRASession()
{
}

std::string ClientRASession::GetSenderID() const
{
	return m_enclaveBase.GetRASenderID();
}

void ClientRASession::SwapConnection(std::unique_ptr<Connection>& connection)
{
	m_connection.swap(connection);
}
