#include "EnclaveBase.h"

#include "Networking/Connection.h"

std::shared_ptr<ClientRASession> EnclaveBase::GetRASession()
{
	std::unique_ptr<Connection> emptyConnection;
	return GetRASession(emptyConnection);
}

bool EnclaveBase::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, std::unique_ptr<Connection>& connection)
{
	return false;
}
