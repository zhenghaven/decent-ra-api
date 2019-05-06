#pragma once

#include <string>

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

		class ConnectionHandler
		{
		public:
			ConnectionHandler() = default;

			virtual ~ConnectionHandler() {}

			virtual bool ProcessSmartMessage(const std::string& category, ConnectionBase& connection) = 0;
		};
	}
}
