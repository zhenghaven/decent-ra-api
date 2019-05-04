#pragma once

#include <list>
#include <utility>
#include <memory>
#include <atomic>
#include <mutex>

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

		class ConnectionPoolBase
		{
		public: //static member:

			static constexpr char sk_serverAskMsg = '?';

			static constexpr char sk_clientWakeMsg = 'W';

			static void ClientAckKeepAlive(ConnectionBase& cnt);

			static void ClientWakePeer(ConnectionBase& cnt);

			static void ServerAsk(ConnectionBase& cnt);

			static void ServerWaitWakeUpMsg(ConnectionBase& cnt);

		public:
			ConnectionPoolBase() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	maxInCnt 	Maximum number of in-coming connection from ALL peer.
			 * \param	maxOutCnt	Maximum number of out-coming connection PER peer.
			 */
			ConnectionPoolBase(size_t maxInCnt);

			//Copy is not allowed
			ConnectionPoolBase(const ConnectionPoolBase&) = delete;

			//Move is not allowed
			ConnectionPoolBase(ConnectionPoolBase&&) = delete;

			virtual ~ConnectionPoolBase();

			//Copy is not allowed
			ConnectionPoolBase& operator=(const ConnectionPoolBase&) = delete;

			//Move is not allowed
			ConnectionPoolBase& operator=(ConnectionPoolBase&&) = delete;

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
			virtual bool HoldInComingConnection(ConnectionBase& cnt);

			/** \brief	Terminate oldest idle connection from the queue. */
			virtual void TerminateOldestIdleConnection();

			/**
			 * \brief	Gets the maximum number of in-coming connection.
			 *
			 * \return	The maximum number of in-coming connection.
			 */
			const size_t& GetMaxInConnection() const noexcept { return m_maxInCnt; }

		protected:

			virtual void AddOneAndCheckCapacity();

			virtual void AddConnection2Queue(ConnectionBase& cnt);

			/**
			 * \brief	Removes the cnt from the queue. This is called when the connection is
			 * 			finished/terminated.
			 *
			 * \param [in,out]	cnt	connection reference.
			 */
			virtual void RemoveFromQueue(ConnectionBase& cnt);

		private:
			const size_t m_maxInCnt;

			//Count for number of in-coming connection
			std::atomic<std::uint_fast64_t> m_inCntCount;

			std::mutex m_serverQueueMutex;
			std::list<ConnectionBase*> m_serverQueue;
		};
	}
}
