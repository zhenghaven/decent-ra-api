#pragma once

#include <vector>
#include <utility>
#include <mutex>
#include <atomic>

namespace Decent
{
	namespace Net
	{
		class TlsCommLayer;

		//TODO:
		//class TlsCntPairBase
		//{
		//public:
		//	virtual TlsCommLayer & GetTlsCommLayer() = 0;
		//};

		class TlsConnectionPool
		{
		//public: //static member:
			//typedef std::pair<std::mutex, std::vector<TlsCntPairBase> > MapItemType;

		public:
			TlsConnectionPool() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	maxInCnt 	Maximum number of in-coming connection from ALL peer.
			 * \param	maxOutCnt	Maximum number of out-coming connection PER peer.
			 */
			TlsConnectionPool(size_t maxInCnt, size_t maxOutCnt);

			//Copy is not allowed
			TlsConnectionPool(const TlsConnectionPool&) = delete;

			//Move is not allowed
			TlsConnectionPool(TlsConnectionPool&&) = delete;

			virtual ~TlsConnectionPool();

			//Copy is not allowed
			TlsConnectionPool& operator=(const TlsConnectionPool&) = delete;

			//Move is not allowed
			TlsConnectionPool& operator=(TlsConnectionPool&&) = delete;

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
			virtual bool HoldInComingConnection(TlsCommLayer& tls);

			/**
			 * \brief	Gets the maximum number of in-coming connection.
			 *
			 * \return	The maximum number of in-coming connection.
			 */
			const size_t& GetMaxInConnection() const noexcept { return m_maxInCnt; }

			/**
			 * \brief	Gets maximum number of out-coming connection.
			 *
			 * \return	The maximum number of out-coming connection.
			 */
			const size_t& GetMaxOutConnection() const noexcept { return m_maxOutCnt; }

			/**
			 * \brief	Gets current number of in-coming connection count.
			 *
			 * \return	The current number of in-coming connection count.
			 */
			uint64_t GetCurrentInConnectionCount() const noexcept { return m_inCntCount; }

		protected:

		private:
			const size_t m_maxInCnt;
			const size_t m_maxOutCnt;

			//Count for number of in-coming connection
			std::atomic<std::uint_fast64_t> m_inCntCount;
		};
	}
}
