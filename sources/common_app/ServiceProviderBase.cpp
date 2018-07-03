#include "ServiceProviderBase.h"

#include "Networking/Connection.h"

ServiceProviderBase::~ServiceProviderBase()
{
}

std::shared_ptr<ServiceProviderRASession> ServiceProviderBase::GetRASession()
{
	std::unique_ptr<Connection> emptyConnection;
	return GetRASession(emptyConnection);
}
