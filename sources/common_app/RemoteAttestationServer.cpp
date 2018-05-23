#include "RemoteAttestationServer.h"

using namespace boost::asio;

RemoteAttestationServer::RemoteAttestationServer(uint32_t ipAddr, uint16_t portNum) :
	m_RAServerIO(new io_service()),
	m_RAServerAcc(new ip::tcp::acceptor(*m_RAServerIO, ip::tcp::endpoint(ip::address_v4(ipAddr), portNum)))
{
}

RemoteAttestationServer::~RemoteAttestationServer()
{
	delete m_RAServerIO;
	delete m_RAServerAcc;
}