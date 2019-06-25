#pragma once

#include <memory>
#include <list>
#include <map>
#include <atomic>
#include <mutex>

namespace Decent
{
	namespace Tools
	{
		template<typename KeyType, typename ItemType>
		class SharedCachingQueue
		{
		public: //static member:
			typedef std::list<std::pair<std::shared_ptr<ItemType>, KeyType> > QueueType;
			typedef std::map<KeyType, std::list<typename QueueType::iterator> > IndexType;

		public:
			SharedCachingQueue() = delete;

			SharedCachingQueue(const size_t cacheSize) :
				m_queueSize(cacheSize),
				m_itemCount(0)
			{}

			virtual ~SharedCachingQueue()
			{}

			/**
			 * \brief	Puts new item to the cache queue.
			 *
			 * \param 		  	key 	The key.
			 * \param [in,out]	item	The item.
			 */
			virtual void Put(const KeyType& key, std::shared_ptr<ItemType> item, bool duplicate)
			{
				if (m_queueSize == 0)
				{
					return;
				}

				if (!duplicate)
				{
					auto idxIt = m_index.find(key);
					if (idxIt != m_index.end() && idxIt->second.size() > 0)
					{
						//Don't make a duplication
						return;
					}
				}

				PutNew(key, item);

				const std::uint_fast64_t prevCount = m_itemCount++;
				if (prevCount >= m_queueSize)
				{
					//queue is full, remove the oldest one.
					RemoveOldest();
				}
			}

			/**
			 * \brief	Gets a item from the cache using the given key
			 *
			 * \param	key	The key associated with the value.
			 *
			 * \return	A std::shared_ptr&lt;ItemType&gt; If nothing is found in the queue, nullptr will be
			 * 			returned.
			 */
			virtual std::shared_ptr<ItemType> Get(const KeyType& key)
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);
				
				auto idxIt = m_index.find(key);
				if (idxIt == m_index.end() || idxIt->second.size() == 0)
				{
					//No available item in the queue.
					return nullptr;
				}
				else
				{
					//Some item is available in the queue.
					auto qIt = idxIt->second.front();
					std::shared_ptr<ItemType> res = qIt->first;

					m_queue.splice(m_queue.end(), m_queue, qIt);
					idxIt->second.splice(idxIt->second.end(), idxIt->second, idxIt->second.begin());

					return res;
				}
			}

			/** \brief	Clears this cache to its blank/initial state */
			virtual void Clear()
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);

				m_queue.clear();
				m_index.clear();
				m_itemCount = 0;
			}

			/**
			 * \brief	Gets cache size
			 *
			 * \return	The cache size.
			 */
			const size_t& GetCacheSize() const noexcept { return m_queueSize; }

			/**
			 * \brief	Gets current cached count
			 *
			 * \return	The current cached count.
			 */
			uint64_t GetCurrentCachedCount() const noexcept { return m_itemCount; }

		protected:
			virtual void PutNew(const KeyType& key, std::shared_ptr<ItemType> item)
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);
				auto it = m_queue.insert(m_queue.end(), std::make_pair(item, key));

				m_index[key].push_back(it);

				//This function doesn't increment the count.
			}

			virtual void RemoveOldest()
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);

				auto it = m_index.find(m_queue.front().second);
				if (it != m_index.end())
				{
					RemoveIndexFront(m_index, it);
				}

				m_queue.pop_front();

				m_itemCount--;
			}

			static void RemoveIndexFront(IndexType& poolIdx, typename IndexType::iterator& idxIt)
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

			static void RemoveIndexBack(IndexType& poolIdx, typename IndexType::iterator& idxIt)
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
			const size_t m_queueSize;

			std::atomic<std::uint_fast64_t> m_itemCount;

			std::mutex m_queueMutex;
			QueueType m_queue;
			IndexType m_index;
		};
	}
}
