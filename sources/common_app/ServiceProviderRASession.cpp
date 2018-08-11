#include "ServiceProviderRASession.h"

#include <sgx_tcrypto.h>

#include "../common/CryptoTools.h"

#include "Networking/Connection.h"

#include "ServiceProviderBase.h"

ServiceProviderRASession::ServiceProviderRASession(std::unique_ptr<Connection>& connection, ServiceProviderBase & serviceProviderBase) :
	m_serviceProviderBase(serviceProviderBase)
{
	m_connection.swap(connection);
	
	sgx_ec256_public_t signPubKey;
	serviceProviderBase.GetRASPSignPubKey(signPubKey);
	m_raSenderID = SerializePubKey(signPubKey);
}

ServiceProviderRASession::~ServiceProviderRASession()
{
}

std::string ServiceProviderRASession::GetSenderID() const
{
	return m_raSenderID;
}

void ServiceProviderRASession::SwapConnection(std::unique_ptr<Connection>& connection)
{
	m_connection.swap(connection);
}
