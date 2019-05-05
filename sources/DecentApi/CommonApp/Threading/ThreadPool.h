#pragma once

#include <memory>
#include <vector>
#include <queue>
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
		 * \brief	A thread pool. There are limited number of workers (i.e. threads) in this pool. All
		 * 			the tasks will be put into a task pool, and workers will grab tasks from the pool
		 * 			once they are free. Thus, please keep in mind that if the task is very long, it will
		 * 			occupy the worker, and tasks in the pool will no be able to be executed. Moreover, an
		 * 			attempt adding task function is given, so that, if all worker are busy at the moment,
		 * 			the task will not be added to the pool.
		 */
		class ThreadPool
		{
		public:
			ThreadPool() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param 		  	maxPoolSize			The maximum size of the pool.
			 * \param [in,out]	mainThreadWorker	The reference to the main thread asynchronous worker.
			 * 										Please make sure this worker will stay alive as long as the
			 * 										main thread is alive.
			 */
			ThreadPool(size_t maxPoolSize, MainThreadAsynWorker& mainThreadWorker);

			/** \brief	Destructor. Terminate will be called here. */
			virtual ~ThreadPool();

			/**
			 * \brief	Attempt to add a task set to the pool. If all workers are busy, task set will not be
			 * 			added, and function will return false; otherwise, task set will be added, and
			 * 			function will return true. Note: This function is thread-safe.
			 *
			 * \exception	Decent::RuntimeException	thrown when the taskset given is a null pointer.
			 *
			 * \param [in,out]	taskset	The unique pointer to the taskset. After the task set is added to the
			 * 							pool, the ownership will be transferred to the pool, and thus, this
			 * 							pointer will be null afterward.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			virtual bool AttemptAddTaskSet(std::unique_ptr<TaskSet>& taskset);

			/**
			 * \brief	Adds a task set to the pool. This function will add the task to the pool without
			 * 			checking if all works are busy. If all workers are busy, the task set will be waiting
			 * 			until some worker is available. Even though it does not check for free workers, this
			 * 			function still has the same overhead as the attempting one, so that that one can work
			 * 			properly. Note: This function is thread-safe.
			 *
			 * \exception	Decent::RuntimeException	thrown when the taskset given is a null pointer; Or
			 * 											when this function is called but the thread pool is
			 * 											already called to terminate.
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
			 * \brief	Gets maximum pool size
			 *
			 * \return	The maximum pool size.
			 */
			size_t GetMaxPoolSize() const { return m_maxPoolSize; }

		protected:
			virtual bool AddTaskSetInternal(std::unique_ptr<TaskSet>& taskset, bool addAnyway);

			/**
			 * \brief	If there is a free worker, get that space and return true; otherwise, return false.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			virtual bool OccupyFreeSpace();

			/**
			 * \brief	Check if worker count approached the max number workers. If not, add a new worker and
			 * 			assign the work to it (It only make sense to add a new worker when there is task),
			 * 			and return true. If yes, return false.
			 *
			 * \param [in,out]	taskset	The task set.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			virtual bool AddWorker(std::unique_ptr<TaskSet>& taskset);

			/**
			 * \brief	Define the procedures for workers.
			 *
			 * \param	mutex  	The mutex.
			 * \param	taskPtr	The task pointer.
			 */
			virtual void Worker(std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr);

		private:
			const size_t m_maxPoolSize;

			std::atomic<bool> m_isTerminated;

			MainThreadAsynWorker& m_mainThreadWorker;

			std::atomic<std::int_fast64_t> m_freeWorkerCount;
			std::atomic<std::uint_fast64_t> m_workerCount;
			std::atomic<bool> m_isWorkerPoolFull;

			std::mutex m_taskQueueMutex;
			std::queue<std::unique_ptr<TaskSet> > m_taskQueue;
			std::condition_variable m_taskQueueSignal;

			std::mutex m_workerPoolMutex;
			std::vector<std::unique_ptr<WorkerItem> > m_workerPool;
		};
	}
}
