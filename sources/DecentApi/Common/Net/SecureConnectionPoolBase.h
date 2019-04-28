#pragma once

#include <utility>
#include <memory>
#include <atomic>

namespace Decent
{
	namespace Net
	{
		class SecureCommLayer;
		class ConnectionBase;

		class CntPair
		{
		public:
			CntPair(std::unique_ptr<ConnectionBase>&& cnt, std::unique_ptr<SecureCommLayer>&& tls);

			CntPair(std::unique_ptr<ConnectionBase>& cnt, std::unique_ptr<SecureCommLayer>& tls);

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

		class SecureConnectionPoolBase
		{
		public: //static member:

			static void ClientAckKeepAlive(CntPair& cntPair);

		public:
			SecureConnectionPoolBase() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	maxInCnt 	Maximum number of in-coming connection from ALL peer.
			 * \param	maxOutCnt	Maximum number of out-coming connection PER peer.
			 */
			SecureConnectionPoolBase(size_t maxInCnt);

			//Copy is not allowed
			SecureConnectionPoolBase(const SecureConnectionPoolBase&) = delete;

			//Move is not allowed
			SecureConnectionPoolBase(SecureConnectionPoolBase&&) = delete;

			virtual ~SecureConnectionPoolBase();

			//Copy is not allowed
			SecureConnectionPoolBase& operator=(const SecureConnectionPoolBase&) = delete;

			//Move is not allowed
			SecureConnectionPoolBase& operator=(SecureConnectionPoolBase&&) = delete;

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
			virtual bool HoldInComingConnection(SecureCommLayer& secComm);

			/**
			 * \brief	Gets the maximum number of in-coming connection.
			 *
			 * \return	The maximum number of in-coming connection.
			 */
			const size_t& GetMaxInConnection() const noexcept { return m_maxInCnt; }

		protected:

		private:
			const size_t m_maxInCnt;

			//Count for number of in-coming connection
			std::atomic<std::uint_fast64_t> m_inCntCount;
		};
	}
}
