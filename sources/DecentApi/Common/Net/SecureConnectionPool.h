#pragma once

#include "SecureConnectionPoolBase.h"

#include "../make_unique.h"
#include "../Tools/CachingQueue.h"

namespace Decent
{
	namespace Ra
	{
		class States;
	}

	namespace Net
	{
		template<typename MapKeyType>
		class SecureConnectionPool : public SecureConnectionPoolBase
		{
		public: //static member:
			//typedef uint64_t MapKeyType;
			typedef std::list<std::pair<CntPair, typename MapKeyType> > CntPoolType;
			typedef std::map<typename MapKeyType, std::list<typename CntPoolType::iterator> > PoolIndexType;

		public:
			SecureConnectionPool(size_t maxInCnt, size_t maxOutCnt) :
				SecureConnectionPoolBase(maxInCnt),
				m_cachingQueue(maxOutCnt)
			{}

			virtual ~SecureConnectionPool()
			{}

			virtual void Put(const MapKeyType& addr, CntPair&& cntPair)
			{
				try
				{
					SecureConnectionPoolBase::ClientAckKeepAlive(cntPair);
				}
				catch (const std::exception&) { return; }

				m_cachingQueue.Put(addr, Tools::make_unique<CntPair>(std::forward<CntPair>(cntPair)));
			}

			virtual CntPair Get(const MapKeyType& addr, Ra::States& state)
			{
				std::unique_ptr<CntPair> cntPairPtr = m_cachingQueue.Get(addr);

				if (cntPairPtr)
				{
					try
					{
						SecureConnectionPoolBase::ClientWakePeer(*cntPairPtr);
						return std::move(*cntPairPtr);
					}
					catch (const std::exception&)
					{
						//Peer closed the connection
					}
				}

				//When no connection in cache, or peer closed connection.
				return GetNew(addr, state);
			}

			virtual CntPair GetAny(const MapKeyType& fallbackAddr, Ra::States& state, MapKeyType& cntedAddr)
			{
				std::pair<std::unique_ptr<CntPair>, MapKeyType> cntPairPtr = m_cachingQueue.GetAnyRecentlyAdded();

				if (cntPairPtr.first)
				{
					try
					{
						SecureConnectionPoolBase::ClientWakePeer(*cntPairPtr.first);
						cntedAddr = cntPairPtr.second;
						return std::move(*cntPairPtr.first);
					}
					catch (const std::exception&)
					{
						//Peer closed the connection
					}
				}

				//When no connection in cache, or peer closed connection.
				cntedAddr = fallbackAddr;
				return GetNew(fallbackAddr, state);
			}

			virtual CntPair GetNew(const MapKeyType& addr, Ra::States& state) = 0;

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
			Tools::CachingQueue<MapKeyType, CntPair> m_cachingQueue;
		};
	}
}
