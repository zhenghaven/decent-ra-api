#pragma once

#include <memory>
class Connection;

class CommSession
{
public:
	void SwapConnection(std::unique_ptr<Connection>& inConnection)
	{
		m_connection.swap(inConnection);
	}

protected:
	std::unique_ptr<Connection> m_connection;
};
