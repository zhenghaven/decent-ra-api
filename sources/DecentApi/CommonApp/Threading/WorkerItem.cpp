#include "WorkerItem.h"

#include <thread>
#include <mutex>

#include "TaskSet.h"

using namespace Decent::Threading;

WorkerItem::WorkerItem(std::unique_ptr<std::thread>&& thread, std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr) :
	m_thread(std::forward<std::unique_ptr<std::thread> >(thread)),
	m_mutex(std::forward<std::shared_ptr<std::mutex> >(mutex)), 
	m_taskPtr(std::forward<std::shared_ptr<std::unique_ptr<TaskSet> > >(taskPtr))
{
}

WorkerItem::WorkerItem(WorkerItem && other) :
	m_thread(std::forward<std::unique_ptr<std::thread> >(other.m_thread)),
	m_mutex(std::forward<std::shared_ptr<std::mutex> >(other.m_mutex)),
	m_taskPtr(std::forward<std::shared_ptr<std::unique_ptr<TaskSet> > >(other.m_taskPtr))
{
}

WorkerItem::~WorkerItem()
{
	Kill();
}

void WorkerItem::Kill()
{
	std::unique_lock<std::mutex> taskLock(*m_mutex, std::defer_lock);
	if (!taskLock.try_lock())
	{
		//task is probably started, kill it.
		(*m_taskPtr)->KillMainTask();
	}
	//Otherwise, task has not been executed yet. As long as the terminate flag is set, the worker won't proceed.
	
	m_thread->join();
}
