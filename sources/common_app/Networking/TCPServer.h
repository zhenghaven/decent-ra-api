#pragma once

#include "Server.h"

#include <cstdint>
#include <memory>

//#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

class Connection;

namespace boost {
	namespace asio {
		class io_context;
		typedef io_context io_service;
		//template <typename Protocol> class basic_socket_acceptor;
		//namespace ip {
		//	class tcp;
		//	typedef basic_socket_acceptor<tcp> acceptor;
		//}
	} // namespace asio
} // namespace boost

class TCPServer : virtual public Server
{
public:
	TCPServer() = delete;
	TCPServer(uint32_t ipAddr, uint16_t portNum);
	virtual ~TCPServer();
	
	///Warning: Blocking method! This method will be blocked until a connection is accepted.
	virtual std::unique_ptr<Connection> AcceptConnection() override;

protected:
	std::shared_ptr<boost::asio::io_service> m_serverIO;
	std::unique_ptr<boost::asio::ip::tcp::acceptor> m_serverAcc;
};