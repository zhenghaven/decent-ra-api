#pragma once

#include <memory>
#include <string>

class Connection;
class ServiceProviderBase;

class ServiceProviderRASession
{
public:
	ServiceProviderRASession() = delete;
	ServiceProviderRASession(std::unique_ptr<Connection>& connection, ServiceProviderBase& serviceProviderBase);
	virtual ~ServiceProviderRASession();

	virtual bool ProcessServerSideRA() = 0;

	virtual std::string GetSenderID() const;

	void SwapConnection(std::unique_ptr<Connection>& connection);

protected:
	std::unique_ptr<Connection> m_connection;
	ServiceProviderBase& m_serviceProviderBase;
	std::string m_raSenderID;
};
