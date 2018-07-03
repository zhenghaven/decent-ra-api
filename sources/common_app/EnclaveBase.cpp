#include "EnclaveBase.h"

#include "Networking/Connection.h"

EnclaveBase::EnclaveBase()
{
}

EnclaveBase::~EnclaveBase()
{
}

std::shared_ptr<ClientRASession> EnclaveBase::GetRASession()
{
	std::unique_ptr<Connection> emptyConnection;
	return GetRASession(emptyConnection);
}
