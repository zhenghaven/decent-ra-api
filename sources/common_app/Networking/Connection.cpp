#include "Connection.h"

#include <cstdlib>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#include <json/json.h>

#include "../Common.h"
#include "../../common/JsonTools.h"

using namespace boost::asio;

Connection::Connection(std::shared_ptr<boost::asio::io_service> ioService, boost::asio::ip::tcp::acceptor & acceptor, size_t bufferSize) :
	m_ioService(ioService),
	m_socket(std::make_unique<ip::tcp::socket>(acceptor.accept())),
	m_buffer(std::string(bufferSize, '\0'))
{
}

Connection::Connection(uint32_t ipAddr, uint16_t portNum, size_t bufferSize) :
	m_ioService(std::make_shared<io_service>()),
	m_socket(std::make_unique<ip::tcp::socket>(*m_ioService)),
	m_buffer(std::string(bufferSize, '\0'))
{
	m_socket->connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
}

Connection::~Connection()
{
}

size_t Connection::Send(const std::string & msg)
{
	size_t res = m_socket->send(boost::asio::buffer(msg.data(), msg.size() + 1));
	LOGI("Sent Msg: %s\n", msg.c_str());
	return res;
}

size_t Connection::Send(const Json::Value & msg)
{
	return Connection::Send(msg.toStyledString());
}

size_t Connection::Send(const std::vector<uint8_t>& msg)
{
	size_t res = m_socket->send(boost::asio::buffer(msg.data(), msg.size()));
	LOGI("Sent Binary with size %llu\n", msg.size());
	return res;
}

size_t Connection::Receive(std::string & msg)
{
	size_t actualSize = m_socket->receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	m_buffer[actualSize] = '\0';
	msg.resize(actualSize + 1);
	std::memcpy(&msg[0], m_buffer.data(), actualSize + 1);
	LOGI("Recv Msg: %s\n", msg.c_str());
	return actualSize;
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
	size_t actualSize = m_socket->receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	m_buffer[actualSize] = '\0';
	msg.resize(actualSize);
	std::memcpy(&msg[0], m_buffer.data(), actualSize);
	LOGI("Recv Binary with size %llu\n", actualSize);
	return actualSize;
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
