#pragma once

#include <memory>
#include <string>

class ClientRASession;
class DecentralizedEnclave;
class Connection;
class EnclaveBase;

class DecentralizedRASession
{
public:
	DecentralizedRASession() = delete;
	DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveBase& hardwareEnclave);
	
	virtual ~DecentralizedRASession();

	virtual bool ProcessClientSideRA();

	virtual bool ProcessServerSideRA();

	void AssignConnection(std::unique_ptr<Connection>& inConnection);

	void SwapConnection(std::unique_ptr<Connection>& inConnection);

protected:
	std::shared_ptr<ClientRASession> m_hardwareSession;
	std::unique_ptr<Connection> m_connection;
	EnclaveBase& m_hardwareEnclave;

	virtual bool SendReverseRARequest(const std::string& senderID);

	virtual bool RecvReverseRARequest();

private:

};
