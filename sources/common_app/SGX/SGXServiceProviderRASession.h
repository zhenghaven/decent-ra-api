#pragma once

#include "../ServiceProviderRASession.h"

class SGXServiceProvider;
class IASConnector;
class SGXRAMessage0Send;
namespace Json
{
	class Value;
}

class SGXServiceProviderRASession : public ServiceProviderRASession
{
public:
	SGXServiceProviderRASession() = delete;
	SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProvider& serviceProviderBase, const IASConnector& ias);
	SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProvider& serviceProviderBase, const IASConnector& ias, const Json::Value& jsonMsg);
	SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProvider& serviceProviderBase, const IASConnector& ias, const SGXRAMessage0Send& msg0s);
	virtual ~SGXServiceProviderRASession();

	virtual bool ProcessServerSideRA() override;

protected:
	SGXServiceProvider& m_sgxSP;
	const IASConnector& m_ias;
	const std::string k_remoteSideID;
};
