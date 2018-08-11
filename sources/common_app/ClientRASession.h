#pragma once

#include <memory>
#include <string>

class Connection;
class EnclaveBase;

class ClientRASession
{

public:
	ClientRASession() = delete;

	//Caution! Blocking constructors!
	ClientRASession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase);

	virtual ~ClientRASession();

	virtual bool ProcessClientSideRA() = 0;

	virtual std::string GetSenderID() const;

	void SwapConnection(std::unique_ptr<Connection>& connection);

protected:
	std::unique_ptr<Connection> m_connection;
	EnclaveBase& m_enclaveBase;
	std::string m_raSenderID;
};