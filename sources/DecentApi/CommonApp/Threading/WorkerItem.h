#pragma once

#include <memory>

namespace std
{
	class thread;
	class mutex;
}

namespace Decent
{
	namespace Threading
	{
		class TaskSet;

		class WorkerItem
		{
		public:
			WorkerItem() = delete;

			WorkerItem(std::unique_ptr<std::thread>&& thread, std::shared_ptr<std::mutex> mutex, std::shared_ptr<std::unique_ptr<TaskSet> > taskPtr);

			WorkerItem(WorkerItem&& other);

			virtual ~WorkerItem();

			void Kill();

		private:
			std::unique_ptr<std::thread> m_thread;
			std::shared_ptr<std::mutex> m_mutex;
			std::shared_ptr<std::unique_ptr<TaskSet> > m_taskPtr;
		};
	}
}
