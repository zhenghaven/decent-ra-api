#include "Server.h"

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "Connection.h"

using namespace boost::asio;

Server::Server(uint32_t ipAddr, uint16_t portNum) :
	m_serverIO(std::make_shared<io_service>()),
	m_serverAcc(std::make_unique<ip::tcp::acceptor>(*m_serverIO, ip::tcp::endpoint(ip::address_v4(ipAddr), portNum)))
{
}

Server::~Server()
{
	//delete m_RAServerIO;
	//delete m_RAServerAcc;
}

std::unique_ptr<Connection> Server::AcceptConnection(size_t bufferSize)
{
	std::unique_ptr<Connection> connection(std::make_unique<Connection>(m_serverIO, *m_serverAcc, bufferSize));
	return std::move(connection);
}
