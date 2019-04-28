#include "SingleTaskThreadPool.h"

#include "../../Common/make_unique.h"
#include "../../Common/RuntimeException.h"

#include "TaskSet.h"
#include "MainThreadAsynWorker.h"

using namespace Decent::Threading;

SingleTaskThreadPool::SingleTaskThreadPool(MainThreadAsynWorker & mainThreadWorker, size_t cleanerNum) :
	m_cleanerNum(cleanerNum),
	m_cleanePool(),
	m_isTerminated(false),
	m_mainThreadWorker(mainThreadWorker)
{
	for (size_t i = 0; i < cleanerNum; ++i)
	{
		std::unique_ptr<std::thread> thr = Tools::make_unique<std::thread>(
			[this]() {
			this->Cleaner();
		});

		m_cleanePool.push_back(std::move(thr));
	}
}

SingleTaskThreadPool::~SingleTaskThreadPool()
{
	Terminate();
}

void SingleTaskThreadPool::AddTaskSet(std::unique_ptr<TaskSet>& taskset)
{
	if (!taskset)
	{
		return;
	}
	if (m_isTerminated)
	{
		throw Decent::RuntimeException("AddTask is called when the thread pool is already terminated!");
	}

	std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
	std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr = std::make_shared<std::unique_ptr<TaskSet> >(std::move(taskset));

	std::unique_ptr<std::thread> thr = Tools::make_unique<std::thread>(
		[this, mutex, taskPtr]() {
		this->Worker(mutex, taskPtr);
	});

	WorkerItem workerItem(std::move(thr), mutex, taskPtr);
	std::unique_lock<std::mutex> workerMapLock(m_workerMapMutex);
	if (!m_isTerminated)
	{
		m_workMap.insert(std::make_pair(taskPtr.get(), std::move(workerItem)));
	}
}

void SingleTaskThreadPool::Terminate()
{
	if (m_isTerminated)
	{
		return;
	}

	m_isTerminated = true;

	(m_cleanQueueSignal).notify_all();

	{
		std::unique_lock<std::mutex> workerMapLock(m_workerMapMutex);
		m_workMap.clear();
	}
}

bool SingleTaskThreadPool::IsTerminated() const noexcept
{
	return m_isTerminated;
}

void SingleTaskThreadPool::Worker(std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr)
{
	{
		std::unique_lock<std::mutex> taskLock(*mutex);
		(*taskPtr)->ExecuteMainTask();
	}

	if (!m_isTerminated)
	{
		m_mainThreadWorker.AddTask(*taskPtr);
	}

	if (!m_isTerminated)
	{
		std::unique_lock<std::mutex> cleanQueueLock(m_cleanQueueMutex);
		(m_cleanQueue).push(taskPtr.get());

		cleanQueueLock.unlock();
		(m_cleanQueueSignal).notify_one();
	}
}

void SingleTaskThreadPool::Cleaner()
{
	std::queue<std::unique_ptr<TaskSet>* > localCleanQueue;

	while (!m_isTerminated)
	{
		{
			std::unique_lock<std::mutex> cleanQueueLock(m_cleanQueueMutex);
			m_cleanQueueSignal.wait(cleanQueueLock, [this]() {
				return m_isTerminated || m_cleanQueue.size() > 0;
			});

			if (m_isTerminated)
			{
				return;
			}

			localCleanQueue.swap(m_cleanQueue);
		}

		std::unique_lock<std::mutex> workerMapLock(m_workerMapMutex);
		while (m_cleanQueue.size() > 0)
		{
			auto it = m_workMap.find(m_cleanQueue.front());
			if (it != m_workMap.end())
			{
				m_workMap.erase(it);
			}
			m_cleanQueue.pop();
		}
	}
}
