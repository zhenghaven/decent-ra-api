#pragma once

#include <string>

namespace Decent
{
	namespace Net
	{
		class Connection;

		class CommSession
		{
		public:
			CommSession(Connection& connection) :
				m_connection(connection)
			{}

			virtual ~CommSession() {}

			virtual const std::string GetSenderID() const = 0;

			virtual const std::string GetRemoteReceiverID() const = 0;

		protected:
			Connection & m_connection;
		};
	}
}
