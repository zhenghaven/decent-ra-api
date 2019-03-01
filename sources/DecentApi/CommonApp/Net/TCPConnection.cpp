#include "TCPConnection.h"

#include <array>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#ifdef DEBUG
#include <boost/exception/diagnostic_information.hpp>
#endif // DEBUG

#include "../../Common/Net/NetworkException.h"

using namespace boost::asio;
using namespace Decent::Net;

#ifdef DEBUG
#define RETHROW_EXCEPTION_AS_DECENT_EXCEPTION(UNKNOWN_EXP_MSG) \
		catch (const boost::exception& e) \
		{ \
			std::string errMsg = "Boost Exception:\n"; \
			errMsg += boost::diagnostic_information(e); \
			throw Decent::Net::Exception(errMsg); \
		} \
		catch (...) \
		{ \
			throw Decent::Net::Exception(UNKNOWN_EXP_MSG); \
		}
#else
#define RETHROW_EXCEPTION_AS_DECENT_EXCEPTION(UNKNOWN_EXP_MSG) \
		catch (const std::exception& e) \
		{ \
			throw Decent::Net::Exception(e.what()); \
		} \
		catch (...) \
		{ \
			throw Decent::Net::Exception(UNKNOWN_EXP_MSG); \
		}
#endif // DEBUG

namespace
{
	static std::unique_ptr<ip::tcp::socket> AcceptConnection(TCPConnection::TcpAcceptorType & acceptor)
	{
		try
		{
			return std::make_unique<ip::tcp::socket>(acceptor.accept());
		}
		RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP accept.")
	}

	static std::unique_ptr<io_service> ConstrIoContext()
	{
		try
		{
			return std::make_unique<io_service>();
		}
		RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at io_service constrcution.")
	}

	static std::unique_ptr<ip::tcp::socket> ConstrSocket(io_service& ioCtx)
	{
		try
		{
			return std::make_unique<ip::tcp::socket>(ioCtx);
		}
		RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at tcp socket constrcution.")
	}
}

TCPConnection::TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, TcpAcceptorType & acceptor) :
	m_ioService(ioService),
	m_socket(AcceptConnection(acceptor))
{
}

TCPConnection::TCPConnection(uint32_t ipAddr, uint16_t portNum) :
	m_ioService(ConstrIoContext()),
	m_socket(ConstrSocket(*m_ioService))
{
	try
	{
		m_socket->connect(ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
	}
	RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP connect.")
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
	RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP send.")
}

size_t TCPConnection::ReceiveRaw(void * const bufPtr, const size_t size)
{
	try
	{
		return m_socket->receive(boost::asio::buffer(bufPtr, size));
	}
	RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at TCP receive.")
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
	RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught when getting IPv4 addr.")
}

uint16_t TCPConnection::GetPortNum() const
{
	try
	{
		return m_socket->remote_endpoint().port();
	}
	RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught when getting port num.")
}

uint64_t TCPConnection::GetConnectionID() const
{
	uint64_t res = GetIPv4Addr();
	res = (res << 32);
	res = res | GetPortNum();

	return res;
}
