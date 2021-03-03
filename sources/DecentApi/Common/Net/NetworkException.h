#pragma once

#include "../Exceptions.h"

namespace Decent
{
	namespace Net
	{
		class Exception : public Decent::RuntimeException
		{
		public:
			explicit Exception(const std::string& what_arg) :
				RuntimeException(what_arg)
			{}

			explicit Exception(const char* what_arg) :
				RuntimeException(what_arg)
			{}

		};

		class ServerAddressOccupiedException : public Exception
		{
		public:
			ServerAddressOccupiedException() :
				Exception("The address is occupied by other running server!")
			{}

		};

		class ConnectionClosedException : public Exception
		{
		public:
			ConnectionClosedException() :
				Exception("The connection is closed!")
			{}
		};

		class ConnectionNotEstablished : public Exception
		{
		public:
			ConnectionNotEstablished() :
				Exception("The connection has not established!")
			{}
		};
	}
}
