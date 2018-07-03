#pragma once

#include <memory>
#include <string>

class Connection;
class ServiceProviderRASession;

class ServiceProviderBase
{
public:
	virtual ~ServiceProviderBase();

	virtual std::string GetRASenderID() const = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession(std::unique_ptr<Connection>& connection) = 0;

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession();

};
