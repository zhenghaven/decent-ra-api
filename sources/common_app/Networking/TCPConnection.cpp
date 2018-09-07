#include "TCPConnection.h"

#include <array>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#include <json/json.h>

#include "../Common.h"
#include "../Messages.h"
#include "../../common/JsonTools.h"

using namespace boost::asio;

TCPConnection::TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, boost::asio::ip::tcp::acceptor & acceptor) :
	m_ioService(ioService),
	m_socket(std::make_unique<ip::tcp::socket>(acceptor.accept()))
{
}

TCPConnection::TCPConnection(uint32_t ipAddr, uint16_t portNum) :
	m_ioService(std::make_shared<io_service>()),
	m_socket(std::make_unique<ip::tcp::socket>(*m_ioService))
{
	m_socket->connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
}

TCPConnection::~TCPConnection()
{
	Terminate();
}

size_t TCPConnection::Send(const Messages & msg)
{
	return Send(msg.ToJsonString());
}

size_t TCPConnection::Send(const std::string & msg)
{
	size_t sentSize = Send(msg.data(), msg.size());
	LOGI("Sent Msg (len=%llu): \n%s\n", static_cast<unsigned long long>(sentSize), msg.c_str());
	return sentSize;
}

size_t TCPConnection::Send(const Json::Value & msg)
{
	return Send(msg.toStyledString());
}

size_t TCPConnection::Send(const std::vector<uint8_t>& msg)
{
	size_t sentSize = Send(msg.data(), msg.size());
	LOGI("Sent Binary with size %llu\n", static_cast<unsigned long long>(sentSize));
	return sentSize;
}

size_t TCPConnection::Send(const void * const dataPtr, const size_t size)
{
	uint64_t msgSize = static_cast<unsigned long long>(size);
	std::array<boost::asio::const_buffer, 2> msgBuf = {
		boost::asio::buffer(&msgSize, sizeof(msgSize)),
		boost::asio::buffer(dataPtr, size)
	};

	size_t res = m_socket->send(msgBuf);
	return res > sizeof(msgSize) ? res - sizeof(msgSize) : 0;
}

size_t TCPConnection::Receive(std::string & msg)
{
	uint64_t msgSize = 0;
	uint64_t receivedSize = 0;
	m_socket->receive(boost::asio::buffer(&msgSize, sizeof(msgSize)));
	msg.resize(msgSize);
	while (receivedSize < msgSize)
	{
		receivedSize += m_socket->receive(boost::asio::buffer(&msg[receivedSize], (msgSize - receivedSize)));
	}
	LOGI("Recv Msg (len=%llu): \n%s\n", receivedSize, msg.c_str());
	return receivedSize;
}

size_t TCPConnection::Receive(Json::Value & msg)
{
	std::string buffer;
	size_t res = Receive(buffer);
	bool isValid = ParseStr2Json(msg, buffer);
	return isValid ? res : 0;
}

size_t TCPConnection::Receive(std::vector<uint8_t>& msg)
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

void TCPConnection::Terminate() noexcept
{
	try
	{
		if (m_ioService->stopped())
		{
			m_ioService->stop();
		}
		if (m_socket->is_open())
		{
			m_socket->close();
		}
	}
	catch (...)
	{
		//Just close the connection, no need to throw any exception.
		return;
	}
}

uint32_t TCPConnection::GetIPv4Addr() const
{
	return m_socket->remote_endpoint().address().to_v4().to_uint();
}

uint16_t TCPConnection::GetIPPort() const
{
	return m_socket->remote_endpoint().port();
}

uint64_t TCPConnection::GetConnectionID() const
{
	uint64_t res = GetIPv4Addr();
	res = (res << 32);
	res = res | GetIPPort();

	return res;
}
