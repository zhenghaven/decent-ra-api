#pragma once

#include "../../Common/Net/ConnectionPoolBase.h"
#include "../../Common/Net/ConnectionBase.h"

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Tools/CachingQueue.h"

#include "../Threading/ThreadPool.h"
#include "../Threading/TaskSet.h"

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

		template<typename MapKeyType>
		class ConnectionPool : public ConnectionPoolBase
		{
		public:
			ConnectionPool(size_t maxInCnt, size_t maxOutCnt, size_t workerPoolSize) :
				ConnectionPoolBase(maxInCnt),
				m_cachingQueue(maxOutCnt),
				m_threadPool(workerPoolSize, nullptr)
			{
				for (size_t i = 0; i < workerPoolSize; ++i)
				{
					std::unique_ptr<Threading::TaskSet> task = std::make_unique<Threading::TaskSet>(
						[this]() //Main task
					{
						this->PendingPoolWorker();
					},
						[this]() //Main task killer
					{
						this->Terminate();
					}
					);

					m_threadPool.AddTaskSet(task);
				}
			}

			virtual ~ConnectionPool()
			{
				Terminate();
			}

			void PendingPoolWorker()
			{
				while (!m_isTerminated)
				{
					std::queue<std::pair<MapKeyType, std::unique_ptr<ConnectionBase> > > tmpPool;

					{
						std::unique_lock<std::mutex> pendingPoolLock(m_pendingPoolMutex);
						if (m_pendingPool.size() == 0)
						{
							m_pendingPoolSignal.wait(pendingPoolLock, [this]() {
								return m_isTerminated || m_pendingPool.size() > 0;
							});
						}

						if (!m_isTerminated && m_pendingPool.size() > 0)
						{
							tmpPool.swap(m_pendingPool);
						}
					}

					while (tmpPool.size() > 0)
					{
						Put(tmpPool.front().first, std::move(tmpPool.front().second));
						tmpPool.pop();
					}
				}
			}

			virtual void Terminate()
			{
				m_isTerminated = true;

				m_pendingPoolSignal.notify_all();

				m_threadPool.Terminate();
			}

			virtual void AsycPut(const MapKeyType& addr, std::unique_ptr<ConnectionBase>&& cntPtr)
			{
				if (m_isTerminated)
				{
					return;
				}

				std::unique_lock<std::mutex> pendingPoolLock(m_pendingPoolMutex);

				m_pendingPool.push(std::make_pair(addr, std::forward<std::unique_ptr<ConnectionBase> >(cntPtr)));

				m_pendingPoolSignal.notify_one();
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

			virtual void Put(const MapKeyType& addr, std::unique_ptr<ConnectionBase>&& cntPtr)
			{
				try
				{
					ConnectionPoolBase::ClientAckKeepAlive(*cntPtr);
				}
				catch (const std::exception&) { return; }

				m_cachingQueue.Put(addr, std::forward<std::unique_ptr<ConnectionBase> >(cntPtr));
			}

			Tools::CachingQueue<MapKeyType, ConnectionBase> m_cachingQueue;

			std::atomic<bool> m_isTerminated;

			Threading::ThreadPool m_threadPool;

			std::mutex m_pendingPoolMutex;
			std::condition_variable m_pendingPoolSignal;
			std::queue<std::pair<MapKeyType, std::unique_ptr<ConnectionBase> > > m_pendingPool;
		};
	}
}
