#pragma once

#include "ConnectionPoolBase.h"
#include "ConnectionBase.h"

#include "../make_unique.h"
#include "../Tools/CachingQueue.h"

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

		template<typename MapKeyType>
		class ConnectionPool : public ConnectionPoolBase
		{
		public:
			ConnectionPool(size_t maxInCnt, size_t maxOutCnt) :
				ConnectionPoolBase(maxInCnt),
				m_cachingQueue(maxOutCnt)
			{}

			virtual ~ConnectionPool()
			{}

			virtual void Put(const MapKeyType& addr, std::unique_ptr<ConnectionBase>&& cntPtr)
			{
				try
				{
					ConnectionPoolBase::ClientAckKeepAlive(*cntPtr);
				}
				catch (const std::exception&) { return; }

				m_cachingQueue.Put(addr, std::forward<std::unique_ptr<ConnectionBase> >(cntPtr));
			}

			virtual std::unique_ptr<ConnectionBase> Get(const MapKeyType& addr)
			{
				std::unique_ptr<ConnectionBase> cntPtr = m_cachingQueue.Get(addr);

				if (cntPtr)
				{
					try
					{
						ConnectionPoolBase::ClientWakePeer(*cntPtr);
						return std::move(cntPtr);
					}
					catch (const std::exception&)
					{
						//Peer closed the connection
					}
				}

				//When no connection in cache, or peer closed connection.
				return GetNew(addr);
			}

			virtual std::pair<std::unique_ptr<ConnectionBase>, MapKeyType> GetAny(const MapKeyType& fallbackAddr)
			{
				std::pair<std::unique_ptr<ConnectionBase>, MapKeyType> cntPtr = m_cachingQueue.GetAnyRecentlyAdded();

				if (cntPtr.first)
				{
					try
					{
						ConnectionPoolBase::ClientWakePeer(*cntPtr.first);
						return std::move(cntPtr);
					}
					catch (const std::exception&)
					{
						//Peer closed the connection
					}
				}

				//When no connection in cache, or peer closed connection.
				return std::make_pair(GetNew(fallbackAddr), fallbackAddr);
			}

			virtual std::unique_ptr<ConnectionBase> GetNew(const MapKeyType& addr) = 0;

			/**
			* \brief	Gets maximum number of out-coming connection.
			*
			* \return	The maximum number of out-coming connection.
			*/
			const size_t& GetMaxOutConnection() const noexcept { return m_cachingQueue.GetCacheSize(); }

			/**
			* \brief	Gets current number of out-coming connection count.
			*
			* \return	The current number of out-coming connection count.
			*/
			uint64_t GetCurrentOutConnectionCount() const noexcept { return m_cachingQueue.GetCurrentCachedCount(); }

		private:
			Tools::CachingQueue<MapKeyType, ConnectionBase> m_cachingQueue;
		};
	}
}
