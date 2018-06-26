#pragma once

#include "RemoteAttestationSession.h"

#include <memory>

class IASConnector;

class SGXRASession : public RemoteAttestationSession
{
public:
	SGXRASession() = delete;

	//Caution! Blocking constructors!
	SGXRASession(std::unique_ptr<Connection>& m_connection, std::shared_ptr<IASConnector> iasConnector);

	~SGXRASession();

	virtual bool ProcessClientSideRA(EnclaveBase& enclave) override;

	virtual bool ProcessServerSideRA(EnclaveBase& enclave) override;

protected:
	std::shared_ptr<IASConnector> m_iasConnector;

private:

};
