#pragma once

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

class Connection
{
public:
	Connection() = delete;
	Connection(std::shared_ptr<boost::asio::io_service> ioService, boost::asio::ip::tcp::acceptor& acceptor, size_t bufferSize = 5000U);
	Connection(uint32_t ipAddr, uint16_t portNum, size_t bufferSize = 5000U);
	~Connection();

	virtual size_t Send(const std::string& msg);
	virtual size_t Send(const Json::Value& msg);
	virtual size_t Send(const std::vector<uint8_t>& msg);

	virtual size_t Receive(std::string& msg);
	virtual size_t Receive(Json::Value& msg);
	virtual size_t Receive(std::vector<uint8_t>& msg);

	uint32_t GetIPv4Addr() const;
	uint16_t GetIPPort() const;

	///Connection ID is a combination of IPv4 and Port num.
	uint64_t GetConnectionID() const;

private:
	std::shared_ptr<boost::asio::io_service> m_ioService;
	std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;

	std::string m_buffer;
};
