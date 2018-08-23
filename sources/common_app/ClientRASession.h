#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

class Connection;
class EnclaveBase;

class ClientRASession : public CommSession
{

public:
	ClientRASession() = delete;

	ClientRASession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase);

	virtual ~ClientRASession();

	virtual bool ProcessClientSideRA() = 0;

	virtual std::string GetSenderID() const;

protected:
	EnclaveBase& m_enclaveBase;
	const std::string k_raSenderID;
};