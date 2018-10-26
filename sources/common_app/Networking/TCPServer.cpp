#include "TCPServer.h"

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "TCPConnection.h"

using namespace boost::asio;

TCPServer::TCPServer(uint32_t ipAddr, uint16_t portNum) :
	m_serverIO(std::make_shared<io_service>()),
	m_serverAcc(std::make_unique<ip::tcp::acceptor>(*m_serverIO, ip::tcp::endpoint(ip::address_v4(ipAddr), portNum))),
	m_isTerminated(0)
{
}

TCPServer::~TCPServer()
{
	//delete m_RAServerIO;
	//delete m_RAServerAcc;
}

std::unique_ptr<Connection> TCPServer::AcceptConnection() noexcept
{
	if (m_isTerminated)
	{
		return nullptr;
	}

	try
	{
		std::unique_ptr<Connection> ptr = std::make_unique<TCPConnection>(m_serverIO, *m_serverAcc);
		if (m_isTerminated)
		{
			return nullptr;
		}
		return std::move(ptr);
	}
	catch (const std::exception&)
	{
		return nullptr;
	}
}

bool TCPServer::IsTerminated() noexcept
{
	return m_isTerminated.load();
}

void TCPServer::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}
	m_isTerminated = 1;

	try
	{
		m_serverIO->stop(); //Can't find doc about exception on this call.
		m_serverAcc->cancel();
		m_serverAcc->close();
	}
	catch (...)
	{
		return;
	}
}
