#include "ServiceProviderRASession.h"

#include "Networking/Connection.h"

#include "ServiceProviderBase.h"

ServiceProviderRASession::ServiceProviderRASession(std::unique_ptr<Connection>& connection, ServiceProviderBase & serviceProviderBase) :
	m_serviceProviderBase(serviceProviderBase)
{
	m_connection.swap(connection);
}

ServiceProviderRASession::~ServiceProviderRASession()
{
}

std::string ServiceProviderRASession::GetSenderID() const
{
	return m_serviceProviderBase.GetRASenderID();
}

void ServiceProviderRASession::SwapConnection(std::unique_ptr<Connection>& connection)
{
	m_connection.swap(connection);
}
