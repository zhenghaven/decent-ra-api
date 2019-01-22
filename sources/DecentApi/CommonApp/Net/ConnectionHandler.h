#pragma once

#include <string>

namespace Json
{
	class Value;
}

namespace Decent
{
	namespace Net
	{
		class Connection;

		class ConnectionHandler
		{
		public:
			virtual ~ConnectionHandler() {}

			virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) = 0;
		};
	}
}
