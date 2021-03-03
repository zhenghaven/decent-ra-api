#pragma once

#include "Server.h"

#include <cstdint>

#include <memory>
#include <atomic>
#include <string>

namespace boost {
	namespace asio {
		class executor;
		class io_context;
		typedef io_context io_service;

		template <typename Protocol, typename Executor>
		class basic_socket_acceptor;

		namespace ip
		{
			class tcp;
		} // namespace ip
	} // namespace asio
} // namespace boost

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

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

			/**
			 * \brief	Construct a TCP server.
			 * 			Known exceptions: Decent::Net::Exception
			 *
			 * \param	ipAddr 	The IP address.
			 * \param	portNum	The port number.
			 */
			TCPServer(const std::string& ipAddr, const uint16_t portNum);

			/** \brief	Destructor */
			virtual ~TCPServer() noexcept;

			/**
			 * \brief	Accept an incoming connection.
			 * 			Known exceptions: Decent::Net::Exception
			 * 			Warning: Blocking method! This method will be blocked until a connection is accepted.
			 *
			 * \return	A std::unique_ptr&lt;Connection&gt;
			 */			
			virtual std::unique_ptr<ConnectionBase> AcceptConnection() override;

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
			std::shared_ptr<boost::asio::basic_socket_acceptor<boost::asio::ip::tcp, boost::asio::executor> > m_serverAcc;

			std::atomic<uint8_t> m_isTerminated;
		};
	}
}
