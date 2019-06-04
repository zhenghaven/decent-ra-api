#pragma once

#include <memory>
#include <queue>
#include <map>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include "WorkerItem.h"

namespace std
{
	class thread;
}

namespace Decent
{
	namespace Threading
	{
		class TaskSet;
		class MainThreadAsynWorker;

		/**
		 * \brief	A single task thread pool. All threads in this pool will only perform one task. Once
		 * 			the task is finished, the thread will be joined and cleaned. Thus, as you adding more
		 * 			tasks to the pool, more threads will be created. Please keep in mind, thread creation
		 * 			is expensive.
		 */
		class SingleTaskThreadPool
		{
		public:
			SingleTaskThreadPool() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	mainThreadWorker	The reference to the main thread asynchronous worker. Please make
			 * 								sure this worker will stay alive as long as the main thread is alive.
			 * 								This can be null if there is no main thread job to do.
			 * \param	cleanerNum			(Optional) The number of cleaner.
			 */
			SingleTaskThreadPool(std::shared_ptr<MainThreadAsynWorker> mainThreadWorker, size_t cleanerNum = 1);

			/** \brief	Destructor. Terminate will be called here. */
			virtual ~SingleTaskThreadPool();

			/**
			 * \brief	Create a new thread and give this task set to the new thread. If the pointer is null,
			 * 			this function will immediately return (No effect at all). Note: This function is
			 * 			thread-safe.
			 *
			 * \exception	Decent::RuntimeException	thrown when this function is called but the thread
			 * 											pool is already called to terminate.
			 *
			 * \param [in,out]	taskset	The unique pointer to the taskset. After the task set is added to the
			 * 							pool, the ownership will be transferred to the pool, and thus, this
			 * 							pointer will be null afterward.
			 */
			virtual void AddTaskSet(std::unique_ptr<TaskSet>& taskset);

			/** \brief	Terminates this thread pool Note: thread-safe */
			void Terminate() noexcept;

			/**
			* \brief	Query if this thread pool is terminated. Note: thread-safe
			*
			* \return	True if terminated, false if not.
			*/
			bool IsTerminated() const noexcept;

			/**
			 * \brief	Gets number of cleaners.
			 *
			 * \return	The number of cleaners.
			 */
			size_t GetCleanerNum() const { return m_cleanerNum; }

		protected:
			virtual void Worker(std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr);

			virtual void Cleaner();

		private:
			const size_t m_cleanerNum;
			std::vector<std::unique_ptr<std::thread> > m_cleanerPool;

			std::atomic<bool> m_isTerminated;

			std::weak_ptr<MainThreadAsynWorker> m_mainThreadWorker;

			std::mutex m_workerMapMutex;
			std::map<std::unique_ptr<TaskSet>*, std::unique_ptr<WorkerItem> > m_workMap;

			std::mutex m_cleanQueueMutex;
			std::queue<std::unique_ptr<TaskSet>* > m_cleanQueue;
			std::condition_variable m_cleanQueueSignal;

		};
	}
}
