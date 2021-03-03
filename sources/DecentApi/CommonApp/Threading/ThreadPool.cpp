#include "ThreadPool.h"

#include <thread>

#include "../../Common/make_unique.h"
#include "../../Common/Exceptions.h"
#include "TaskSet.h"
#include "MainThreadAsynWorker.h"

using namespace Decent::Threading;

ThreadPool::ThreadPool(size_t maxPoolSize, std::shared_ptr<MainThreadAsynWorker> mainThreadWorker) :
	m_maxPoolSize(maxPoolSize),
	m_isTerminated(false),
	m_mainThreadWorker(mainThreadWorker),
	m_freeWorkerCount(0),
	m_workerCount(0),
	m_isWorkerPoolFull(false)
{
}

ThreadPool::~ThreadPool()
{
	Terminate();
}

bool ThreadPool::AttemptAddTaskSet(std::unique_ptr<TaskSet>& taskset)
{
	return AddTaskSetInternal(taskset, false);
}

void ThreadPool::AddTaskSet(std::unique_ptr<TaskSet>& taskset)
{
	AddTaskSetInternal(taskset, true);
}

void ThreadPool::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}

	m_isTerminated = true;

	m_taskQueueSignal.notify_all();

	try
	{
		std::unique_lock<std::mutex> threadPoolLock(m_workerPoolMutex);
		m_workerPool.clear();
	} catch (const std::exception&) {}
}

bool ThreadPool::IsTerminated() const noexcept
{
	return m_isTerminated;
}

bool ThreadPool::AddTaskSetInternal(std::unique_ptr<TaskSet>& taskset, bool addAnyway)
{
	if (!taskset)
	{
		throw Decent::RuntimeException("Null pointer for task set is given to the thread pool!");
	}
	if (m_isTerminated)
	{
		throw Decent::RuntimeException("AddTask is called when the thread pool is already terminated!");
	}

	bool gotFreeSpace = OccupyFreeSpace();

	if (!gotFreeSpace && (!m_isWorkerPoolFull) && AddWorker(taskset))
	{
		//If there is no free space, but worker pool is not full and task has been given to the new worker
		// Done!
		return true;
	}
	else if (gotFreeSpace || addAnyway)
	{
		//If we got the free space, or the task should be added anyway
		std::unique_lock<std::mutex> taskQueueLock(m_taskQueueMutex);
		m_taskQueue.push(std::move(taskset));

		taskQueueLock.unlock();
		m_taskQueueSignal.notify_one();
		return true;
	}
	else
	{
		return false;
	}
}

bool ThreadPool::OccupyFreeSpace()
{
	const std::int_fast64_t freeWorker = m_freeWorkerCount--;
	if (freeWorker <= 0)
	{
		//There is no free worker in the worker pool.

		m_freeWorkerCount++;
		return false;
	}
	else
	{
		return true;
	}
}

bool ThreadPool::AddWorker(std::unique_ptr<TaskSet>& taskset)
{
	const std::uint_fast64_t workerCount = m_workerCount++;
	if (workerCount + 1 <= m_maxPoolSize && !m_isTerminated)
	{
		//Yes, we can add one more.
		if (workerCount + 1 == m_maxPoolSize)
		{
			//After adding this worker, pool will be full.
			m_isWorkerPoolFull = true;
		}
		
		const std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
		std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr = std::make_shared<std::unique_ptr<TaskSet> >(std::move(taskset));

		//Create new thread/worker.
		std::unique_ptr<std::thread> thr = Tools::make_unique<std::thread>(
			[this, mutex, taskPtr]() {
			this->Worker(mutex, taskPtr);
		});

		//Add new thread to the pool.
		{
			std::unique_lock<std::mutex> threadPoolLock(m_workerPoolMutex);
			if (m_isTerminated)
			{
				return false;
			}
			std::unique_ptr<WorkerItem> workItem = Tools::make_unique<WorkerItem>(std::move(thr), mutex, taskPtr);
			m_workerPool.push_back(std::move(workItem));
		}

		return true;
	}
	else
	{
		//No, we cannot add any more.
		m_isWorkerPoolFull = true;
		m_workerCount--;
		return false;
	}
}

void ThreadPool::Worker(std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr)
{
	std::unique_ptr<TaskSet>& task = *taskPtr;

	while (!m_isTerminated)
	{
		{
			std::unique_lock<std::mutex> taskLock(*mutex);
			if (!m_isTerminated) //One last check before execute.
			{
				if (task)
				{
					task->ExecuteMainTask();
				}
			}
			else
			{
				return;
			}
		}

		if (m_isTerminated)
		{
			return; //the task probably has not been finished, so don't add to main thread task pool.
		}

		if (!m_mainThreadWorker.expired())
		{
			m_mainThreadWorker.lock()->AddTask(std::move(task));
		}

		//Ask for new task.
		{
			std::unique_lock<std::mutex> taskQueueLock(m_taskQueueMutex);
			if (m_taskQueue.size() == 0)
			{
				m_freeWorkerCount++;

				m_taskQueueSignal.wait(taskQueueLock,
					[this]() -> bool {
					return m_isTerminated || m_taskQueue.size() > 0;
				});
			}

			if (m_taskQueue.size() > 0)
			{
				task.swap(m_taskQueue.front());
				m_taskQueue.pop();
			}
		}
	}
}
