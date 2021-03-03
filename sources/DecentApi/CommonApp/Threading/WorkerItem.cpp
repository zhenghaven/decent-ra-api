#include "WorkerItem.h"

#include <thread>
#include <mutex>

#include "../../Common/Exceptions.h"

#include "TaskSet.h"

using namespace Decent::Threading;

WorkerItem::WorkerItem(std::unique_ptr<std::thread>&& thread, const std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr) :
	m_thread(std::forward<std::unique_ptr<std::thread> >(thread)),
	m_mutex(mutex),
	m_taskPtr(taskPtr)
{
	if (!m_thread || !m_mutex || !m_taskPtr)
	{
		throw RuntimeException("nullptr has been assigned to the WorkerItem.");
	}
}

WorkerItem::~WorkerItem()
{
	Kill();
}

void WorkerItem::Kill()
{
	if (!m_thread)
	{
		return;
	}

	std::unique_lock<std::mutex> taskLock(*m_mutex, std::defer_lock);
	if (!taskLock.try_lock())
	{
		//task is probably started, kill it.
		(*m_taskPtr)->KillMainTask();
	}
	//Otherwise, task has not been executed yet. As long as the terminate flag is set, the worker won't proceed.
	
	m_thread->join();
}
