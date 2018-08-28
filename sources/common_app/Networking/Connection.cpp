#include "Connection.h"

#include <array>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#include <json/json.h>

#include "../Common.h"
#include "../Messages.h"
#include "../../common/JsonTools.h"

using namespace boost::asio;

Connection::Connection(std::shared_ptr<boost::asio::io_service> ioService, boost::asio::ip::tcp::acceptor & acceptor) :
	m_ioService(ioService),
	m_socket(std::make_unique<ip::tcp::socket>(acceptor.accept()))
{
}

Connection::Connection(uint32_t ipAddr, uint16_t portNum) :
	m_ioService(std::make_shared<io_service>()),
	m_socket(std::make_unique<ip::tcp::socket>(*m_ioService))
{
	m_socket->connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
}

Connection::~Connection()
{
}

size_t Connection::Send(const Messages & msg)
{
	return Send(msg.ToJsonString());
}

size_t Connection::Send(const std::string & msg)
{
	uint64_t msgSize = static_cast<unsigned long long>(msg.size());
	std::array<boost::asio::const_buffer, 2> msgBuf = {
		boost::asio::buffer(&msgSize, sizeof(msgSize)),
		boost::asio::buffer(msg.data(), msg.size())
	};
	size_t res = m_socket->send(msgBuf);
	LOGI("Sent Msg: %s\n", msg.c_str());
	return res - sizeof(msgBuf);
}

size_t Connection::Send(const Json::Value & msg)
{
	return Connection::Send(msg.toStyledString());
}

size_t Connection::Send(const std::vector<uint8_t>& msg)
{
	uint64_t msgSize = static_cast<unsigned long long>(msg.size());
	std::array<boost::asio::const_buffer, 2> msgBuf = {
		boost::asio::buffer(&msgSize, sizeof(msgSize)),
		boost::asio::buffer(msg.data(), msg.size())
	};
	size_t res = m_socket->send(msgBuf);
	LOGI("Sent Binary with size %llu\n", msgSize);
	return res - sizeof(msgBuf);
}

size_t Connection::Receive(std::string & msg)
{
	uint64_t msgSize = 0;
	uint64_t receivedSize = 0;
	m_socket->receive(boost::asio::buffer(&msgSize, sizeof(msgSize)));
	msg.resize(msgSize);
	while (receivedSize < msgSize)
	{
		receivedSize += m_socket->receive(boost::asio::buffer(&msg[receivedSize], (msgSize - receivedSize)));
	}
	LOGI("Recv Msg: %s\n", msg.c_str());
	return receivedSize;
}

size_t Connection::Receive(Json::Value & msg)
{
	std::string buffer;
	size_t res = Connection::Receive(buffer);
	bool isValid = ParseStr2Json(msg, buffer);
	return isValid ? res : 0;
}

size_t Connection::Receive(std::vector<uint8_t>& msg)
{
	uint64_t msgSize = 0;
	uint64_t receivedSize = 0;
	m_socket->receive(boost::asio::buffer(&msgSize, sizeof(msgSize)));
	msg.resize(msgSize);
	while (receivedSize < msgSize)
	{
		receivedSize += m_socket->receive(boost::asio::buffer(&msg[receivedSize], (msgSize - receivedSize)));
	}
	LOGI("Recv Binary with size %llu\n", receivedSize);
	return receivedSize;
}

uint32_t Connection::GetIPv4Addr() const
{
	return m_socket->remote_endpoint().address().to_v4().to_uint();
}

uint16_t Connection::GetIPPort() const
{
	return m_socket->remote_endpoint().port();
}

uint64_t Connection::GetConnectionID() const
{
	uint64_t res = GetIPv4Addr();
	res = (res << 32);
	res = res | GetIPPort();

	return res;
}
