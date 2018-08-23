#include "ServiceProviderRASession.h"

#include <sgx_tcrypto.h>

#include "../common/DataCoding.h"

#include "Networking/Connection.h"

#include "ServiceProviderBase.h"

static std::string ConstructSenderID(ServiceProviderBase& serviceProviderBase)
{
	sgx_ec256_public_t signPubKey;
	serviceProviderBase.GetRASPSignPubKey(signPubKey);
	return SerializePubKey(signPubKey);
}

ServiceProviderRASession::ServiceProviderRASession(std::unique_ptr<Connection>& connection, ServiceProviderBase & serviceProviderBase) :
	m_serviceProviderBase(serviceProviderBase),
	k_raSenderID(ConstructSenderID(serviceProviderBase))
{
	m_connection.swap(connection);
}

ServiceProviderRASession::~ServiceProviderRASession()
{
}

std::string ServiceProviderRASession::GetSenderID() const
{
	return k_raSenderID;
}
