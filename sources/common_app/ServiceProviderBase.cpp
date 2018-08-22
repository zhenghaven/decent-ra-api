#include "ServiceProviderBase.h"

#include "Networking/Connection.h"

std::shared_ptr<ServiceProviderRASession> ServiceProviderBase::GetRASession()
{
	std::unique_ptr<Connection> emptyConnection;
	return GetRASession(emptyConnection);
}

bool ServiceProviderBase::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, std::unique_ptr<Connection>& connection)
{
	return false;
}
