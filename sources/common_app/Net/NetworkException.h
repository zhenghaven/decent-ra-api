#pragma once

#include <exception>

namespace Decent
{
	namespace Net
	{
		class Exception : public std::exception
		{
		public:
			Exception()
			{}
			virtual ~Exception()
			{}

			virtual const char* what() const throw()
			{
				return "General Network Exception.";
			}
		};

		class ServerAddressOccupiedException : public Exception
		{
		public:
			ServerAddressOccupiedException()
			{}
			~ServerAddressOccupiedException()
			{}

			virtual const char* what() const throw()
			{
				return "The address is occupied by other running server!";
			}
		};

		class ConnectionClosedException : public Exception
		{
		public:
			ConnectionClosedException()
			{}
			~ConnectionClosedException()
			{}

			virtual const char* what() const throw()
			{
				return "The connection is closed!";
			}
		};
	}
}
