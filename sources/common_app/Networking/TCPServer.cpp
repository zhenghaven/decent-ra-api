#include "TCPServer.h"

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "TCPConnection.h"

using namespace boost::asio;

TCPServer::TCPServer(uint32_t ipAddr, uint16_t portNum) :
	m_serverIO(std::make_shared<io_service>()),
	m_serverAcc(std::make_unique<ip::tcp::acceptor>(*m_serverIO, ip::tcp::endpoint(ip::address_v4(ipAddr), portNum)))
{
}

TCPServer::~TCPServer()
{
	//delete m_RAServerIO;
	//delete m_RAServerAcc;
}

std::unique_ptr<Connection> TCPServer::AcceptConnection()
{
	return std::make_unique<TCPConnection>(m_serverIO, *m_serverAcc);
}
