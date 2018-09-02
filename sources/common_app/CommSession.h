#pragma once

#include <memory>
#include <string>
class Connection;

class CommSession
{
public:
	void SwapConnection(std::unique_ptr<Connection>& inConnection)
	{
		m_connection.swap(inConnection);
	}

	virtual ~CommSession();

	virtual const std::string GetSenderID() const = 0;

	virtual const std::string GetRemoteReceiverID() const = 0;

protected:
	std::unique_ptr<Connection> m_connection;
};
