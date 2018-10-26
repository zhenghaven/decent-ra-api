#include "TCPConnection.h"

#include <array>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

using namespace boost::asio;

TCPConnection::TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, TcpAcceptorType & acceptor) :
	m_ioService(ioService),
	m_socket(std::make_unique<ip::tcp::socket>(acceptor.accept()))
{
}

TCPConnection::TCPConnection(uint32_t ipAddr, uint16_t portNum) :
	m_ioService(std::make_shared<io_service>()),
	m_socket(std::make_unique<ip::tcp::socket>(*m_ioService))
{
	m_socket->connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
}

TCPConnection::~TCPConnection()
{
	Terminate();
}

size_t TCPConnection::SendRaw(const void * const dataPtr, const size_t size)
{
	size_t res = m_socket->send(boost::asio::buffer(dataPtr, size));
	return res;
}

size_t TCPConnection::ReceiveRaw(void * const bufPtr, const size_t size)
{
	return m_socket->receive(boost::asio::buffer(bufPtr, size));
}

void TCPConnection::Terminate() noexcept
{
	try
	{
		if (m_ioService->stopped())
		{
			m_ioService->stop();
		}
		if (m_socket->is_open())
		{
			m_socket->close();
		}
	}
	catch (...)
	{
		//Just close the connection, no need to throw any exception.
		return;
	}
}

uint32_t TCPConnection::GetIPv4Addr() const
{
	return m_socket->remote_endpoint().address().to_v4().to_uint();
}

uint16_t TCPConnection::GetIPPort() const
{
	return m_socket->remote_endpoint().port();
}

uint64_t TCPConnection::GetConnectionID() const
{
	uint64_t res = GetIPv4Addr();
	res = (res << 32);
	res = res | GetIPPort();

	return res;
}
