#include "TaskSet.h"

using namespace Decent::Threading;

TaskSet::TaskSet(TaskType mainTask, TaskType mainTaskKiller, TaskType finalMainThreadTask) :
	m_mainTask(mainTask),
	m_mainTaskKiller(mainTaskKiller),
	m_finalMainThreadTask(finalMainThreadTask)
{
}

TaskSet::~TaskSet()
{
}

void TaskSet::ExecuteMainTask() const
{
	if (m_mainTask)
	{
		m_mainTask();
	}
}

void TaskSet::KillMainTask() const
{
	if (m_mainTaskKiller)
	{
		m_mainTaskKiller();
	}
}

void TaskSet::ExecuteFinalMainThreadTask() const
{
	if (m_finalMainThreadTask)
	{
		m_finalMainThreadTask();
	}
}
