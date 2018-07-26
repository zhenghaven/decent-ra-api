#include "SGXServiceProvider.h"

#include "SGXServiceProviderRASession.h"

SGXServiceProvider::SGXServiceProvider(IASConnector ias) :
	m_ias(ias)
{
}

SGXServiceProvider::~SGXServiceProvider()
{
}
//
//std::string SGXServiceProvider::GetRASenderID() const
//{
//	return m_raSenderID;
//}

std::shared_ptr<ServiceProviderRASession> SGXServiceProvider::GetRASession(std::unique_ptr<Connection>& connection)
{
	return std::make_shared<SGXServiceProviderRASession>(connection, *this, m_ias);
}
