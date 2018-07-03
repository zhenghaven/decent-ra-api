#pragma once

#include "../ClientRASession.h"

#include <memory>

class IASConnector;
class SGXEnclave;

class SGXClientRASession : public ClientRASession
{
public:
	SGXClientRASession() = delete;

	//Caution! Blocking constructors!
	SGXClientRASession(std::unique_ptr<Connection>& m_connection, SGXEnclave& enclave);

	virtual ~SGXClientRASession();

	virtual bool ProcessClientSideRA() override;

protected:
	SGXEnclave& m_sgxEnclave;
};
