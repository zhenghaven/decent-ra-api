#include "RemoteAttestationSession.h"

using namespace boost::asio;

RemoteAttestationSession::RemoteAttestationSession(boost::asio::ip::tcp::acceptor& acceptor, size_t bufferSize) :
	m_ioService(nullptr),
	m_socket(acceptor.accept()),
	m_buffer(std::string(bufferSize, '\0'))
{
}

RemoteAttestationSession::RemoteAttestationSession(uint32_t ipAddr, uint16_t portNum, size_t bufferSize) :
	m_ioService(new io_service()),
	m_socket(ip::tcp::socket(*m_ioService)),
	m_buffer(std::string(bufferSize, '\0'))
{
	m_socket.connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
}

RemoteAttestationSession::~RemoteAttestationSession()
{
	if (m_ioService)
	{
		delete m_ioService;
		m_ioService = nullptr;
	}
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

RemoteAttestationSession::Mode RemoteAttestationSession::GetMode() const
{
	return m_ioService ? RemoteAttestationSession::Mode::Client : RemoteAttestationSession::Mode::Server;
}
