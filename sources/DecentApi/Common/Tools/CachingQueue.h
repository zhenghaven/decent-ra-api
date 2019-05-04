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
		class CachingQueue
		{
		public: //static member:
			typedef std::list<std::pair<std::unique_ptr<ItemType>, KeyType> > QueueType;
			typedef std::map<KeyType, std::list<typename QueueType::iterator> > IndexType;

		public:
			CachingQueue() = delete;

			CachingQueue(const size_t cacheSize) :
				m_queueSize(cacheSize),
				m_itemCount(0)
			{}

			virtual ~CachingQueue()
			{}

			/**
			 * \brief	Puts new item to the cache queue.
			 *
			 * \param 		  	key 	The key.
			 * \param [in,out]	item	The item.
			 */
			virtual void Put(const KeyType& key, std::unique_ptr<ItemType>&& item)
			{
				if (m_queueSize == 0)
				{
					return;
				}

				PutNew(key, std::forward<std::unique_ptr<ItemType> >(item));

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
			 * \return	A std::unique_ptr&lt;ItemType&gt; If nothing is found in the queue, nullptr will be
			 * 			returned.
			 */
			virtual std::unique_ptr<ItemType> Get(const KeyType& key)
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
					std::unique_ptr<ItemType> res = std::move(qIt->first);

					m_queue.erase(qIt);
					m_itemCount--;
					RemoveIndexFront(m_index, idxIt);

					return std::move(res);
				}
			}

			/**
			 * \brief	Gets any recently added item
			 *
			 * \return	a key-item pair that recently added. If nothing is found in the queue, nullptr
			 * 			included in the pair will be returned.
			 */
			virtual std::pair<std::unique_ptr<ItemType>, KeyType> GetAnyRecentlyAdded()
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);
				if (m_queue.size() == 0)
				{
					return std::pair<std::unique_ptr<ItemType>, KeyType>();
				}
				else
				{
					//Some Connection is available in the pool.

					std::unique_ptr<ItemType> resItem = std::move(m_queue.back().first);  //Get item.
					KeyType resKey = std::move(m_queue.back().second);                    //Get key.
					auto idxIt = m_index.find(resKey);         //Find its index.
					if (idxIt != m_index.end())
					{
						RemoveIndexBack(m_index, idxIt);   //Remove the index.
					}

					m_queue.pop_back(); //Remove the item from the pool.
					m_itemCount--;

					return std::make_pair(std::move(resItem), std::move(resKey));
				}
			}

			/**
			 * \brief	Gets any oldest item
			 *
			 * \return	a key-item pair that is oldest in the queue. If nothing is found in the queue, nullptr
			 * 			included in the pair will be returned.
			 */
			virtual std::pair<std::unique_ptr<ItemType>, KeyType> GetAnyOldest()
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);
				if (m_queue.size() == 0)
				{
					return std::pair<std::unique_ptr<ItemType>, KeyType>();
				}
				else
				{
					//Some Connection is available in the pool.

					std::unique_ptr<ItemType> resItem = std::move(m_queue.front().first);  //Get item.
					KeyType resKey = std::move(m_queue.front().second);                    //Get key.
					auto idxIt = m_index.find(m_queue.front().second);         //Find its index.
					if (idxIt != m_index.end())
					{
						RemoveIndexFront(m_index, idxIt);   //Remove the index.
					}

					m_queue.pop_front(); //Remove the item from the pool.
					m_itemCount--;

					return std::make_pair(std::move(resItem), std::move(resKey));
				}
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
			virtual void PutNew(const KeyType& key, std::unique_ptr<ItemType>&& item)
			{
				std::unique_lock<std::mutex> queueLock(m_queueMutex);
				auto it = m_queue.insert(m_queue.end(), std::make_pair(std::forward<std::unique_ptr<ItemType> >(item), key));

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
