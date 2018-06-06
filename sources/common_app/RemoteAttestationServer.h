#pragma once

#include <cstdint>
#include <memory>

//#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

class RemoteAttestationSession;
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

class RemoteAttestationServer
{
public:
	RemoteAttestationServer() = delete;
	RemoteAttestationServer(uint32_t ipAddr, uint16_t portNum);
	~RemoteAttestationServer();
	
	///Warning: Blocking method! This method will be blocked until a connection is accepted.
	virtual std::unique_ptr<Connection> AcceptRAConnection(size_t bufferSize = 5000U) = 0;

protected:
	std::shared_ptr<boost::asio::io_service> m_RAServerIO;
	std::unique_ptr<boost::asio::ip::tcp::acceptor> m_RAServerAcc;
};
