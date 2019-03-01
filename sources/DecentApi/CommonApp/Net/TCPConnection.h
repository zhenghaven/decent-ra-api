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

namespace Decent
{
	namespace Net
	{
		class SmartMessages;

		class TCPConnection : public Connection
		{
		public:
			typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp> TcpSocketType;
			typedef boost::asio::basic_socket_acceptor<boost::asio::ip::tcp> TcpAcceptorType;

			TCPConnection() = delete;

			/**
			 * \brief	Construct TCP connection from a TCP acceptor. Usually this constructor is called by TCPServer.
			 * 			Known exceptions: Decent::Net::Exception
			 *
			 * \param 		  	ioService	The i/o service.
			 * \param [in,out]	acceptor 	The acceptor.
			 */
			TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, TcpAcceptorType& acceptor);

			/**
			 * \brief	Construct TCP connection by connecting to a server. Usually this constructor is called in client side.
			 * 			Known exceptions: Decent::Net::Exception
			 *
			 * \param	ipAddr 	The IP address.
			 * \param	portNum	The port number.
			 */
			TCPConnection(uint32_t ipAddr, uint16_t portNum);

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			TCPConnection(TCPConnection&& rhs) noexcept;

			/** \brief	Destructor */
			virtual ~TCPConnection() noexcept;

			virtual size_t SendRaw(const void* const dataPtr, const size_t size) override;

			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size) override;

			/** \brief	Terminates this TCP connection */
			virtual void Terminate() noexcept override;

			/**
			 * \brief	Gets IPv4 address
			 * 			Known exceptions: Decent::Net::Exception
			 *
			 * \return	The IPv4 address in the form of a 4-Byte-number.
			 */
			uint32_t GetIPv4Addr() const;

			/**
			 * \brief	Gets port number
			 * 			Known exceptions: Decent::Net::Exception
			 *
			 * \return	The port number.
			 */
			uint16_t GetPortNum() const;

			/**
			 * \brief	Connection ID is a combination of IPv4 and Port num.
			 *
			 * \return	The connection identifier.
			 */
			uint64_t GetConnectionID() const;

		private:
			std::shared_ptr<boost::asio::io_service> m_ioService;
			std::unique_ptr<TcpSocketType> m_socket;
		};
	}
}
