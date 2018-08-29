#pragma once

#include "Connection.h"

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>

namespace boost {
	namespace asio {
		class io_context;
		typedef io_context io_service;
		template <typename Protocol> class basic_socket_acceptor;
		//namespace ip {
		//	class tcp;
		//	typedef basic_socket_acceptor<tcp> acceptor;
		//}
	} // namespace asio
} // namespace boost

namespace Json
{
	class Value;
}

class Messages;

class TCPConnection : virtual public Connection
{
public:
	TCPConnection() = delete;
	TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, boost::asio::ip::tcp::acceptor& acceptor);
	TCPConnection(uint32_t ipAddr, uint16_t portNum);
	virtual ~TCPConnection();

	virtual size_t Send(const Messages& msg) override;
	virtual size_t Send(const std::string& msg) override;
	virtual size_t Send(const Json::Value& msg) override;
	virtual size_t Send(const std::vector<uint8_t>& msg) override;
	virtual size_t Send(const void* const dataPtr, const size_t size) override;

	virtual size_t Receive(std::string& msg) override;
	virtual size_t Receive(Json::Value& msg) override;
	virtual size_t Receive(std::vector<uint8_t>& msg) override;

	uint32_t GetIPv4Addr() const;
	uint16_t GetIPPort() const;

	///Connection ID is a combination of IPv4 and Port num.
	uint64_t GetConnectionID() const;

private:
	std::shared_ptr<boost::asio::io_service> m_ioService;
	std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;
};
