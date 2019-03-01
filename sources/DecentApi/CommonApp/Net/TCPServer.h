#pragma once

#include "Server.h"

#include <cstdint>
#include <memory>
#include <atomic>

//#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace boost {
	namespace asio {
		class io_context;
		typedef io_context io_service;
		//template <typename Protocol> class basic_socket_acceptor;
		//namespace ip {
		//	class tcp;
		//	typedef basic_socket_acceptor<tcp> acceptor;
		//}
	} // namespace asio
} // namespace boost

namespace Decent
{
	namespace Net
	{
		class Connection;

		/** \brief	A TCP server. */
		class TCPServer : virtual public Server
		{
		public:
			TCPServer() = delete;

			/**
			 * \brief	Construct a TCP server. 
			 * 			Known exceptions: Decent::Net::Exception
			 *
			 * \param	ipAddr 	The IP address.
			 * \param	portNum	The port number.
			 */
			TCPServer(const uint32_t ipAddr, const uint16_t portNum);

			/** \brief	Destructor */
			virtual ~TCPServer() noexcept;

			/**
			 * \brief	Accept an incoming connection.
			 * 			Known exceptions: Decent::Net::Exception
			 * 			Warning: Blocking method! This method will be blocked until a connection is accepted.
			 *
			 * \return	A std::unique_ptr&lt;Connection&gt;
			 */			
			virtual std::unique_ptr<Connection> AcceptConnection() override;

			/**
			 * \brief	Query if this TCP Server is terminated
			 *
			 * \return	True if terminated, false if not.
			 */
			virtual bool IsTerminated() noexcept override;

			/** \brief	Terminates this TCP Server */
			virtual void Terminate() noexcept override;

		protected:
			std::shared_ptr<boost::asio::io_service> m_serverIO;
			std::unique_ptr<boost::asio::ip::tcp::acceptor> m_serverAcc;

			std::atomic<uint8_t> m_isTerminated;
		};
	}
}
