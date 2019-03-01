#include "TCPServer.h"

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#ifdef DEBUG
#include <boost/exception/diagnostic_information.hpp>
#endif // DEBUG

#include "TCPConnection.h"
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
	static std::unique_ptr<io_service> ConstrIoContext()
	{
		try
		{
			return std::make_unique<io_service>();
		}
		RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at io_service constrcution.")
	}

	static std::unique_ptr<ip::tcp::acceptor> ConstrAcceptor(io_service& serverIO, const uint32_t ipAddr, const uint16_t portNum)
	{
		try
		{
			return std::make_unique<ip::tcp::acceptor>(serverIO, ip::tcp::endpoint(ip::address_v4(ipAddr), portNum));
		}
		RETHROW_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at acceptor constrcution.")
	}
}

TCPServer::TCPServer(const uint32_t ipAddr, const uint16_t portNum) :
	m_serverIO(ConstrIoContext()),
	m_serverAcc(ConstrAcceptor(*m_serverIO, ipAddr, portNum)),
	m_isTerminated(0)
{
}

TCPServer::~TCPServer()
{
}

std::unique_ptr<Connection> TCPServer::AcceptConnection()
{
	if (m_isTerminated)
	{
		throw ConnectionClosedException();
	}

	return  std::make_unique<TCPConnection>(m_serverIO, *m_serverAcc);
}

bool TCPServer::IsTerminated() noexcept
{
	return m_isTerminated.load();
}

void TCPServer::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}
	++m_isTerminated;

	try
	{
		m_serverIO->stop(); //Can't find doc about exception on this call.
	}
	catch (...) {}
	try
	{
		m_serverAcc->cancel();
	}
	catch (...) {}
	try
	{
		m_serverAcc->close();
	}
	catch (...) {}
}
