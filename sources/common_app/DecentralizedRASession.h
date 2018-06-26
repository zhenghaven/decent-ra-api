#pragma once

#include <memory>

class RemoteAttestationSession;
class Connection;

class DecentralizedRASession
{
public:
	DecentralizedRASession() = delete;
	DecentralizedRASession(std::unique_ptr<Connection>& connection, std::shared_ptr<RemoteAttestationSession>& hardwareSession);
	
	virtual ~DecentralizedRASession();

	void AssignConnection(std::unique_ptr<Connection>& inConnection);

	void SwapConnection(std::unique_ptr<Connection>& inConnection);

protected:
	std::shared_ptr<RemoteAttestationSession> m_hardwareSession;
	std::unique_ptr<Connection> m_connection;

private:

};
