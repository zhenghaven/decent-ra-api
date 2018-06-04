#include "RemoteAttestationServer.h"

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

using namespace boost::asio;

RemoteAttestationServer::RemoteAttestationServer(uint32_t ipAddr, uint16_t portNum) :
	m_RAServerIO(std::make_shared<io_service>()),
	m_RAServerAcc(std::make_unique<ip::tcp::acceptor>(*m_RAServerIO, ip::tcp::endpoint(ip::address_v4(ipAddr), portNum)))
{
}

RemoteAttestationServer::~RemoteAttestationServer()
{
	//delete m_RAServerIO;
	//delete m_RAServerAcc;
}