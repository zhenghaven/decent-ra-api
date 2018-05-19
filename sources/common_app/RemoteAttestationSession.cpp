#include "RemoteAttestationSession.h"


RemoteAttestationSession::RemoteAttestationSession(boost::asio::ip::tcp::acceptor& acceptor) :
	m_socket(acceptor.accept())
{
}

RemoteAttestationSession::~RemoteAttestationSession()
{
}

uint32_t RemoteAttestationSession::GetIPv4Addr() const
{
	return m_socket.remote_endpoint().address().to_v4().to_uint();
}

uint16_t RemoteAttestationSession::GetIPPort() const
{
	return m_socket.remote_endpoint().port();
}

uint64_t RemoteAttestationSession::GetConnectionID() const
{
	uint64_t res = GetIPv4Addr();
	res = (res << 32);
	res = res | GetIPPort();

	return res;
}
