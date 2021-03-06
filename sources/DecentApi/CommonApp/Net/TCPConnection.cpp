#include "TCPConnection.h"

#include <array>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#include "NetworkException.h"

using namespace boost::asio;
using namespace Decent::Net;

namespace
{
	static std::unique_ptr<ip::tcp::socket> AcceptConnection(TCPConnection::TcpAcceptorType & acceptor)
	{
		try
		{
			return std::make_unique<ip::tcp::socket>(acceptor.accept());
		}
		RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP accept.")
	}

	static std::unique_ptr<io_service> ConstrIoContext()
	{
		try
		{
			return std::make_unique<io_service>();
		}
		RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at io_service constrcution.")
	}

	static std::unique_ptr<ip::tcp::socket> ConstrSocket(io_service& ioCtx)
	{
		try
		{
			return std::make_unique<ip::tcp::socket>(ioCtx);
		}
		RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at tcp socket constrcution.")
	}
}

uint32_t TCPConnection::GetIpAddressFromStr(const std::string & ipAddrStr)
{
	return boost::asio::ip::address_v4::from_string(ipAddrStr).to_uint();
}

TCPConnection::TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, std::shared_ptr<TcpAcceptorType> acceptor) :
	m_ioService(ioService),
	m_socket(AcceptConnection(*acceptor))
{
	try
	{
		m_socket->set_option(ip::tcp::no_delay(true));
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP connect.")
}

TCPConnection::TCPConnection(uint32_t ipAddr, uint16_t portNum) :
	m_ioService(ConstrIoContext()),
	m_socket(ConstrSocket(*m_ioService))
{
	try
	{
		m_socket->connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
		m_socket->set_option(ip::tcp::no_delay(true));
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP connect.")
}

TCPConnection::TCPConnection(TCPConnection && rhs) noexcept :
	m_ioService(std::move(rhs.m_ioService)),
	m_socket(std::move(rhs.m_socket))
{
}

TCPConnection::~TCPConnection()
{
	Terminate();
}

size_t TCPConnection::SendRaw(const void * const dataPtr, const size_t size)
{
	try 
	{
		return m_socket->send(boost::asio::buffer(dataPtr, size));
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP send.")
}

size_t TCPConnection::RecvRaw(void * const bufPtr, const size_t size)
{
	try
	{
		return m_socket->receive(boost::asio::buffer(bufPtr, size));
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP receive.")
}

void TCPConnection::Terminate() noexcept
{
	try
	{
		if (m_ioService->stopped()) { m_ioService->stop(); }
	}//Just close the connection, no need to handle any exception.
	catch (...) { }

	try
	{
		if (m_socket->is_open()) { m_socket->close(); }
	}
	catch (...) { }
}

uint32_t TCPConnection::GetIPv4Addr() const
{
	try
	{
		return m_socket->remote_endpoint().address().to_v4().to_uint();
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught when getting IPv4 addr.")
}

uint16_t TCPConnection::GetPortNum() const
{
	try
	{
		return m_socket->remote_endpoint().port();
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught when getting port num.")
}

uint64_t TCPConnection::GetConnectionID() const
{
	return CombineIpAndPort(GetIPv4Addr(), GetPortNum());
}
