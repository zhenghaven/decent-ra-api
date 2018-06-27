#pragma once

#include "../RemoteAttestationSession.h"

#include <memory>

class IASConnector;
class SGXEnclave;

class SGXRASession : public RemoteAttestationSession
{
public:
	SGXRASession() = delete;

	//Caution! Blocking constructors!
	SGXRASession(std::unique_ptr<Connection>& m_connection, SGXEnclave& enclave, IASConnector& iasConnector);

	~SGXRASession();

	virtual bool ProcessClientSideRA() override;

	virtual bool ProcessServerSideRA() override;

protected:
	IASConnector& m_iasConnector;

private:
	SGXEnclave& m_enclave;
};
