#pragma once

#include <memory>

namespace Decent
{
	namespace Net
	{
		class Connection;

		class Server
		{
		public:
			virtual ~Server() noexcept {}

			/**
			 * \brief	Accept an incoming connection.
			 * 			Child classes should only throw Decent::Net::Exception for this function call.
			 * 			Warning: Blocking method! This method will be blocked until a connection is accepted.
			 *
			 * \return	A std::unique_ptr&lt;Connection&gt;
			 */
			virtual std::unique_ptr<Connection> AcceptConnection() = 0;

			/**
			 * \brief	Query if this server is terminated
			 *
			 * \return	True if terminated, false if not.
			 */
			virtual bool IsTerminated() noexcept = 0;

			/** \brief	Terminates this server */
			virtual void Terminate() noexcept = 0;
		};
	}
}
