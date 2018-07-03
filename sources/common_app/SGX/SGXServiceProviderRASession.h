#pragma once

#include "../ServiceProviderRASession.h"

class SGXServiceProvider;
class IASConnector;

class SGXServiceProviderRASession : public ServiceProviderRASession
{
public:
	SGXServiceProviderRASession() = delete;
	SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProvider& serviceProviderBase, IASConnector& ias);
	virtual ~SGXServiceProviderRASession();

	virtual bool ProcessServerSideRA() override;

protected:
	SGXServiceProvider& m_sgxSP;
	IASConnector& m_ias;
};
