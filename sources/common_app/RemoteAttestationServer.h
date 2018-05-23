#pragma once

#include <cstdint>

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

class RemoteAttestationSession;

class RemoteAttestationServer
{
public:
	RemoteAttestationServer() = delete;
	RemoteAttestationServer(uint32_t ipAddr, uint16_t portNum);
	~RemoteAttestationServer();

	///Warning: Blocking method! This method will be blocked until a connection is accepted.
	virtual RemoteAttestationSession* AcceptRAConnection() = 0;

protected:
	
	boost::asio::io_service* m_RAServerIO;
	boost::asio::ip::tcp::acceptor* m_RAServerAcc;
};
