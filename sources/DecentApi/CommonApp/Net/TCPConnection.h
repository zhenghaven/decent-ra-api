#pragma once

#include "../../Common/Net/ConnectionBase.h"

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

//#include <boost/asio/ip/tcp.hpp>

namespace boost 
{
	namespace asio 
	{
		class executor;
		class io_context;
		typedef io_context io_service;

		template <typename Protocol, typename Executor>
		class basic_socket_acceptor;

		template <typename Protocol, typename Executor>
		class basic_stream_socket;

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
		class TCPConnection : public ConnectionBase
		{
		public: //static members:
			typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, boost::asio::executor> TcpSocketType;
			typedef boost::asio::basic_socket_acceptor<boost::asio::ip::tcp, boost::asio::executor> TcpAcceptorType;

			/**
			 * \brief	Gets IP address in 32-bit number from string in form of X.X.X.X
			 *
			 * \param	ipAddrStr	The IP address string.
			 *
			 * \return	The IP address in 32-bit number.
			 */
			static uint32_t GetIpAddressFromStr(const std::string& ipAddrStr);

			/**
			 * \brief	Combine IP and port number into a 64-bit number in the format of 
			 * 			IP(32-bits)|0x0000|Port(16-bits).
			 *
			 * \param	ip  	The IP.
			 * \param	port	The port.
			 *
			 * \return	An uint64_t number.
			 */
			static uint64_t CombineIpAndPort(uint32_t ip, uint16_t port)
			{
				uint64_t res = ip;
				res <<= 32;

				return res | static_cast<uint64_t>(port);
			}

		public:
			TCPConnection() = delete;

			/**
			 * \brief	Construct TCP connection from a TCP acceptor. Usually this constructor is called by
			 * 			TCPServer.
			 *
			 * \exception	Decent::Net::Exception	It is thrown when failed to accept connection from client.
			 *
			 * \param 		  	ioService	The i/o service.
			 * \param [in,out]	acceptor 	The acceptor.
			 */
			TCPConnection(std::shared_ptr<boost::asio::io_service> ioService, std::shared_ptr<TcpAcceptorType> acceptor);

			/**
			 * \brief	Construct TCP connection by connecting to a server. Usually this constructor is
			 * 			called in client side.
			 *
			 * \exception	Decent::Net::Exception	It is thrown when failed to connect remote server.
			 *
			 * \param	ipAddr 	The IP address.
			 * \param	portNum	The port number.
			 */
			TCPConnection(uint32_t ipAddr, uint16_t portNum);

			/**
			 * \brief	Construct TCP connection by connecting to a server. Usually this constructor is
			 * 			called in client side.
			 *
			 * \exception	Decent::Net::Exception	It is thrown when failed to connect remote server.
			 *
			 * \param	ipAddr 	The IP address.
			 * \param	portNum	The port number.
			 */
			TCPConnection(const std::string& ipAddr, uint16_t portNum) :
				TCPConnection(GetIpAddressFromStr(ipAddr), portNum)
			{}

			/**
			 * \brief	Construct TCP connection by connecting to a server. Usually this constructor is
			 * 			called in client side.
			 *
			 * \exception	Decent::Net::Exception	It is thrown when failed to connect remote server.
			 *
			 * \param	addr	The address, which is IP &amp; port in the format of IP(32-
			 * 					bits)|0x0000|Port(16-bits).
			 */
			TCPConnection(uint64_t addr) :
				TCPConnection(static_cast<uint32_t>((addr >> 32) & 0xFFFFFFFFU), 
					static_cast<uint16_t>(addr & 0xFFFF))
			{}

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			TCPConnection(TCPConnection&& rhs) noexcept;

			/** \brief	Destructor */
			virtual ~TCPConnection() noexcept;

			virtual size_t SendRaw(const void* const dataPtr, const size_t size) override;

			virtual size_t RecvRaw(void* const bufPtr, const size_t size) override;

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
			 * \brief	Connection ID is a combination of IPv4 and Port number in the format of 
			 * 			IP(32-bits)|0x0000|Port(16-bits).
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
