#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

class Connection;
class ServiceProviderBase;

class ServiceProviderRASession : public CommSession
{
public:
	ServiceProviderRASession() = delete;
	ServiceProviderRASession(std::unique_ptr<Connection>& connection, ServiceProviderBase& serviceProviderBase);
	virtual ~ServiceProviderRASession();

	virtual bool ProcessServerSideRA() = 0;

	virtual std::string GetSenderID() const;

protected:
	ServiceProviderBase& m_serviceProviderBase;
	const std::string k_raSenderID;
};
