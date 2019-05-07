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

			/**
			 * \brief	Process the smart message. This function is called by the SmartServer to process the
			 * 			message.
			 *
			 * \param 		  	category   	The category of the message.
			 * \param [in,out]	connection 	The incoming connection. Note: the connection object is owned by
			 * 								the Smart Server.
			 * \param [out]	  	freeHeldCnt	[out] A pointer to a previously held connection. If it returns
			 * 								nullptr, nothing will be freed. If it returns non-null, the
			 * 								corresponding held connection will be freed (or put into
			 * 								connection pool for connection reuse).
			 *
			 * \return	True if the current connection (presented by 'connection' parameter) need to be held.
			 */
			virtual bool ProcessSmartMessage(const std::string& category, ConnectionBase& connection, ConnectionBase*& freeHeldCnt) = 0;
		};
	}
}
