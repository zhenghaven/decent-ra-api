#pragma once

#include "SecureConnectionPoolBase.h"

#include <list>
#include <map>
#include <mutex>

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
				m_maxOutCnt(maxOutCnt)
			{}

			virtual ~SecureConnectionPool()
			{}

			virtual void Put(const MapKeyType& addr, CntPair&& cntPair)
			{
				try
				{
					SecureConnectionPoolBase::ClientAckKeepAlive(cntPair);
				} catch (const std::exception&) {}

				const std::uint_fast64_t prevCount = m_outCntCount++;
				if (prevCount == m_maxOutCnt)
				{
					//Pool is full, remove the oldest one.
					RemoveOldest();
				}
				PutNew(addr, std::forward<CntPair>(cntPair));
			}

			virtual CntPair Get(const MapKeyType& addr, Ra::States& state)
			{
				std::unique_lock<std::mutex> cntPoolLock(m_cntPoolMutex);
				//LOGI("Pool Size: %llu", m_cntPool.size());
				//LOGI("Index Size: %llu", m_poolIndex.size());
				//LOGI("Count Size: %llu", m_outCntCount.load());
				auto idxIt = m_poolIndex.find(addr);
				if (idxIt == m_poolIndex.end() || idxIt->second.size() == 0)
				{
					//No available connection in the pool.
					cntPoolLock.unlock();
					return GetNew(addr, state);
				}
				else
				{
					//Connection is available in the pool.
					auto poolIt = idxIt->second.front();
					CntPair res = std::move(poolIt->first);

					m_cntPool.erase(poolIt);
					m_outCntCount--;
					RemoveIndexFront(m_poolIndex, idxIt);

					//!!!!! We done with the pool, unlock it.
					cntPoolLock.unlock();

					try
					{
						SecureConnectionPoolBase::ClientWakePeer(res);
					}
					catch (const std::exception&)
					{
						//Peer closed the connection
						return GetNew(addr, state);
					}

					return res;
				}
			}

			virtual CntPair GetAny(const MapKeyType& fallbackAddr, Ra::States& state, MapKeyType& cntedAddr)
			{
				std::unique_lock<std::mutex> cntPoolLock(m_cntPoolMutex);
				if (m_cntPool.size() == 0)
				{
					//No connection available, fallback to new connection.
					cntPoolLock.unlock();
					cntedAddr = fallbackAddr;
					return GetNew(fallbackAddr, state);
				}
				else
				{
					//Some Connection is available in the pool.
					
					CntPair res = std::move(m_cntPool.back().first);  //Get newly added connection pair.
					cntedAddr = m_cntPool.back().second;              //Get the address for this connectino pair.
					auto idxIt = m_poolIndex.find(cntedAddr);         //Find its index.
					if (idxIt != m_poolIndex.end())
					{
						RemoveIndexBack(m_poolIndex, idxIt); //Remove the index.
					}
					
					m_cntPool.pop_back(); //Remove the item from the pool.
					m_outCntCount--;

					//!!!!! We done with the pool, unlock it.
					cntPoolLock.unlock();

					try
					{
						SecureConnectionPoolBase::ClientWakePeer(res);
					}
					catch (const std::exception&)
					{
						//Peer closed the connection
						cntedAddr = fallbackAddr;
						return GetNew(fallbackAddr, state);
					}

					return res;
				}
			}

			virtual CntPair GetNew(const MapKeyType& addr, Ra::States& state) = 0;

			/**
			* \brief	Gets maximum number of out-coming connection.
			*
			* \return	The maximum number of out-coming connection.
			*/
			const size_t& GetMaxOutConnection() const noexcept { return m_maxOutCnt; }

			/**
			* \brief	Gets current number of out-coming connection count.
			*
			* \return	The current number of out-coming connection count.
			*/
			uint64_t GetCurrentOutConnectionCount() const noexcept { return m_outCntCount; }

		protected:
			virtual void PutNew(const MapKeyType& addr, CntPair&& cntPair)
			{
				std::unique_lock<std::mutex> cntPoolLock(m_cntPoolMutex);
				m_cntPool.push_back(std::make_pair(std::forward<CntPair>(cntPair), addr));
				auto it = m_cntPool.end();
				it--;

				m_poolIndex[addr].push_back(it);
			}

			virtual void RemoveOldest()
			{
				std::unique_lock<std::mutex> cntPoolLock(m_cntPoolMutex);

				auto it = m_poolIndex.find(m_cntPool.front().second);
				if (it != m_poolIndex.end())
				{
					RemoveIndexFront(m_poolIndex, it);
				}

				m_cntPool.pop_front();

				m_outCntCount--;
			}

			static void RemoveIndexFront(PoolIndexType& poolIdx, typename PoolIndexType::iterator& idxIt)
			{
				if (idxIt->second.size() <= 1)
				{
					poolIdx.erase(idxIt);
				}
				else
				{
					idxIt->second.pop_front();
				}
			}

			static void RemoveIndexBack(PoolIndexType& poolIdx, typename PoolIndexType::iterator& idxIt)
			{
				if (idxIt->second.size() <= 1)
				{
					poolIdx.erase(idxIt);
				}
				else
				{
					idxIt->second.pop_back();
				}
			}

		private:
			const size_t m_maxOutCnt;

			std::atomic<std::uint_fast64_t> m_outCntCount;

			std::mutex m_cntPoolMutex;
			CntPoolType m_cntPool;
			PoolIndexType m_poolIndex;
		};
	}
}