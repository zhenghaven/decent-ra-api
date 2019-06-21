#pragma once

#include "ConnectionPoolBase.h"

namespace Decent
{
	namespace Net
	{
		class SecureCommLayer;
		class ConnectionBase;

		class CntPair
		{
		public:
			CntPair(std::unique_ptr<ConnectionBase> cnt, std::unique_ptr<SecureCommLayer> tls);

			//Copy is not allowed
			CntPair(const CntPair&) = delete;

			CntPair(CntPair&& rhs);

			virtual ~CntPair();

			virtual SecureCommLayer & GetCommLayer();

			virtual ConnectionBase & GetConnection();

			CntPair& operator=(const CntPair& rhs) = delete;

			CntPair& operator=(CntPair&& rhs);

			CntPair& Swap(CntPair& other);

		private:
			std::unique_ptr<ConnectionBase> m_cnt;
			std::unique_ptr<SecureCommLayer> m_comm;
		};

		class SecureConnectionPoolBase : public ConnectionPoolBase
		{
		public: //static member:

			static void ClientAckKeepAlive(CntPair& cntPair);

			static void ClientWakePeer(CntPair& cntPair);

			static void ServerAsk(SecureCommLayer& secComm);

			static void ServerWaitWakeUpMsg(SecureCommLayer& secComm);

		public:

			using ConnectionPoolBase::ConnectionPoolBase;

			/**
			 * \brief	Hold the in-coming connection. This function will check the count for incoming
			 * 			connection. If there are still spaces to hold incoming connection, this function will
			 * 			follow the Decent keep-alive protocol, hold the connection, and wait for wake-up
			 * 			message. Once the held connection is waken up by the peer, this function will return
			 * 			true. If there is no more space, or the peer terminate the connection, this function
			 * 			will return true. Note: Always check return value before proceed. This function is thread-safe.
			 *
			 * \param [in,out]	tls	The TLS communication layer.
			 *
			 * \return	True if the connection is still alive, false if it is not.
			 */
			virtual bool HoldInComingConnection(ConnectionBase& cnt, SecureCommLayer& secComm);

		};
	}
}
