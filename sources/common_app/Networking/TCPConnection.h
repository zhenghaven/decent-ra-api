#pragma once

#include "Connection.h"

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

//#include <boost/asio/ip/tcp.hpp>

namespace boost 
{
	namespace asio 
	{
		class io_context;
		typedef io_context io_service;
		template <typename Protocol> class basic_socket_acceptor;
		template <typename Protocol> class basic_stream_socket;
		namespace ip 
		{
			class tcp;
			//typedef basic_socket_acceptor<tcp> acceptor;
			//typedef basic_stream_socket<tcp> socket;
		} // namespace ip
	} // namespace asio
} // namespace boost


namespace Json
{
	class Value;
}

class Messages;

class TCPConnection : public Connection
{
public:
	typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp> TcpSocketType;
	typedef boost::asio::basic_socket_acceptor<boost::asio::ip::tcp> TcpAcceptorType;
	
	TCPConnection() = delete;
	TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, TcpAcceptorType& acceptor);
	TCPConnection(uint32_t ipAddr, uint16_t portNum);
	virtual ~TCPConnection() noexcept;

	virtual size_t SendRaw(const void* const dataPtr, const size_t size) override;

	virtual size_t ReceiveRaw(void* const bufPtr, const size_t size) override;

	virtual void Terminate() noexcept override;

	uint32_t GetIPv4Addr() const;
	uint16_t GetIPPort() const;

	///Connection ID is a combination of IPv4 and Port num.
	uint64_t GetConnectionID() const;

private:
	std::shared_ptr<boost::asio::io_service> m_ioService;
	std::unique_ptr<TcpSocketType> m_socket;
};
