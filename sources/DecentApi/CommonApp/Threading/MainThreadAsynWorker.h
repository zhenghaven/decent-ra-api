#pragma once

#include <memory>
#include <queue>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace std
{
	class thread;
}

namespace Decent
{
	namespace Threading
	{
		class TaskSet;

		/**
		 * \brief	A main thread asynchronous worker. Any other thread can add task to here so that it
		 * 			will be executed by the main thread. "Asynchronous" means the task is executed
		 * 			asynchronously; the task is added to the queue by one thread, and only will be
		 * 			executed when the update function is called by the main thread. Note: the tasks will
		 * 			be executed by the main thread only if the instance of this class is held by the main
		 * 			thread and the update function is called in the main thread.
		 */
		class MainThreadAsynWorker
		{
		public:
			MainThreadAsynWorker();
			
			virtual ~MainThreadAsynWorker();

			/**
			 * \brief	Adds a main thread task. If the pointer to the task is empty, this function will
			 * 			immediately return (No effect at all). Note: this function is thread-safe.
			 *
			 * \param [in,out]	task	The unique pointer points to the task set (But only the main thread
			 * 							task will be executed).
			 */
			void AddTask(std::unique_ptr<TaskSet> task);

			/**
			 * \brief	Execute tasks that are available in the queue. Note: The queue is not polled at once,
			 * 			instead, it is polled every time a task is done. This function should only be called
			 * 			in the main thread.
			 *
			 * \param	maxCount	(Optional) The maximum number to be executed. If a negative number is
			 * 						given, this function will keep executing until nothing is available in the
			 * 						queue.
			 *
			 * \return	Total number of tasks that has been executed.
			 */
			virtual size_t Update(const int64_t maxCount = -1);

			/**
			 * \brief	Execute tasks until an interrupt signal is received. If no task is available for the
			 * 			moment, this function will go to sleep and wait for new tasks.
			 *
			 * \return	Total number of tasks that has been executed.
			 */
			virtual size_t UpdateUntilInterrupt();

		protected:

			/**
			 * \brief	Catch the interrupt signal and set the interruptFlag;
			 *
			 * \param [out]	interruptFlag	(Output) The interrupt flag.
			 * \param [out]	stopFunc	 	(Output) The stop function.
			 * \param 	   	maxCount	 	(Optional) maximum number interrupt signal to be caught. If a
			 * 								negative number is given this function will keep catching
			 * 								interrupt signal until the stop function is called.
			 */
			virtual void InterruptSignalCatcher(std::atomic<bool>& interruptFlag, std::function<void()>& stopFunc, const int64_t maxCount = 1);

			/**
			 * \brief	Sets up the interrupt signal catcher
			 *
			 * \param [out]	interruptFlag	(Output) The interrupt flag.
			 * \param [out]	stopFunc	 	(Output) The stop function.
			 * \param 	   	maxCount	 	(Optional) maximum number interrupt signal to be caught. If a
			 * 								negative number is given the catcher thread will keep catching
			 * 								interrupt signal until the stop function is called.
			 *
			 * \return	A std::unique_ptr&lt;std::thread&gt that point to the interrupt signal catcher thread;
			 */
			virtual std::unique_ptr<std::thread> SetupInterruptSignalCatcher(std::atomic<bool>& interruptFlag, std::function<void()>& stopFunc, const int64_t maxCount = 1);

		private:
			std::mutex m_taskQueueMutex;
			std::queue<std::unique_ptr<TaskSet> > m_taskQueue;
			std::condition_variable m_taskQueueSignal;
		};
	}
}
