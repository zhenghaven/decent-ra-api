#include "MainThreadAsynWorker.h"

#include <boost/asio/signal_set.hpp>
#include <boost/asio/io_service.hpp>

#include "../../Common/make_unique.h"
#include "TaskSet.h"

using namespace Decent;
using namespace Decent::Threading;

MainThreadAsynWorker::MainThreadAsynWorker()
{
}

MainThreadAsynWorker::~MainThreadAsynWorker()
{
}

void MainThreadAsynWorker::AddTask(std::unique_ptr<TaskSet> task)
{
	if (!task)
	{
		return;
	}

	std::unique_lock<std::mutex> taskQueueLock(m_taskQueueMutex);

	m_taskQueue.push(std::move(task));

	taskQueueLock.unlock();
	m_taskQueueSignal.notify_one();
}

size_t MainThreadAsynWorker::Update(const int64_t maxCount)
{
	std::unique_ptr<TaskSet> task;

	for (size_t i = 0; maxCount < 0 || static_cast<int64_t>(i) < maxCount; ++i)
	{
		{
			std::unique_lock<std::mutex> taskQueueLock(m_taskQueueMutex);
			if (m_taskQueue.size() == 0)
			{
				//No more task available, return;
				return i + 1;
			}

			//Has some task to do.
			task = std::move(m_taskQueue.front());
			m_taskQueue.pop();
		}
		task->ExecuteFinalMainThreadTask();
	}

	return maxCount;
}

size_t MainThreadAsynWorker::UpdateUntilInterrupt()
{
	std::atomic<bool> isInterrupted = false;
	size_t i = 0;

	std::function<void()> stopFunc;
	std::unique_ptr<std::thread> inptCatcherThread = SetupInterruptSignalCatcher(isInterrupted, stopFunc);
	std::unique_ptr<TaskSet> task;
	while (true)
	{
		{
			std::unique_lock<std::mutex> taskQueueLock(m_taskQueueMutex);
			if (m_taskQueue.size() == 0)
			{
				//No more task available, wait
				m_taskQueueSignal.wait(taskQueueLock, 
					[this, &isInterrupted]() -> bool {
					return isInterrupted || m_taskQueue.size() > 0;
				});

				if (isInterrupted)
				{
					//It is stopped by interrupt
					inptCatcherThread->join();
					return i;
				}
			}

			//Has some task to do.
			task = std::move(m_taskQueue.front());
			m_taskQueue.pop();
		}

		task->ExecuteFinalMainThreadTask();
		++i;
		task.reset();
	}
}

void MainThreadAsynWorker::InterruptSignalCatcher(std::atomic<bool>& interruptFlag, std::function<void()>& stopFunc, const int64_t maxCount)
{
	if (maxCount == 0)
	{
		return;
	}

	std::shared_ptr<boost::asio::io_service> io_service = std::make_shared<boost::asio::io_service>();
	std::shared_ptr<std::atomic<std::int_fast64_t> > caughtCount = std::make_shared<std::atomic<std::int_fast64_t> >(0);

	stopFunc = [io_service]()
	{
		if (!io_service->stopped())
		{
			io_service->stop();
		}
	};

	boost::asio::signal_set signals(*io_service, SIGINT);
	signals.async_wait([this, &interruptFlag, io_service, maxCount, caughtCount](const boost::system::error_code& error, int signal_number)
	{
		interruptFlag = true;
		m_taskQueueSignal.notify_all();
		++(*caughtCount);
		if ((maxCount > 0 && (*caughtCount) >= maxCount) && !io_service->stopped())
		{
			io_service->stop();
		}
	});

	io_service->run();
}

std::unique_ptr<std::thread> MainThreadAsynWorker::SetupInterruptSignalCatcher(std::atomic<bool>& interruptFlag, std::function<void()>& stopFunc, const int64_t maxCount)
{
	return Tools::make_unique<std::thread>(
		[this, &interruptFlag, &stopFunc]() {
		InterruptSignalCatcher(interruptFlag, stopFunc);
	});
}
