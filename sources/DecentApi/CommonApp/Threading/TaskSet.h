#pragma once

#include <functional>

namespace Decent
{
	namespace Threading
	{
		class TaskSet
		{
		public: //static members:
			typedef std::function<void()> TaskType;

		public:
			TaskSet() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	mainTask		   	The main task, the major task of this task set.
			 * \param	mainTaskKiller	   	The main task killer, a function that can terminate the main task
			 * 								immediately (it is usually called at thread-pool/program tear
			 * 								down phase).
			 * \param	finalTask		   	(Optional) The final task that will be executed after the main
			 * 								task is done (Done normally; NOT killed by the main task killer).
			 * 								Usually this task is executed by some thread pool cleaner, of
			 * 								which could only has limited number, thus, the final task should
			 * 								be as simple as possible in this case.
			 * \param	finalTaskKiller	   	(Optional) The final task killer, a function that can terminate
			 * 								the final task immediately.
			 * \param	finalMainThreadTask	(Optional) The final main thread task, the task that will be sent
			 * 								to the main thread to execute AFTER both the main task and final
			 * 								task are done.
			 */
			TaskSet(TaskType mainTask, TaskType mainTaskKiller, 
			TaskType finalMainThreadTask = TaskType());

			/** \brief	Destructor */
			virtual ~TaskSet();

			/**
			 * \brief	Gets the const reference to the main task
			 *
			 * \return	The main task.
			 */
			const TaskType& GetMainTask() const { return m_mainTask; }

			/**
			 * \brief	Gets the const reference to the main task killer
			 *
			 * \return	The main task killer.
			 */
			const TaskType& GetMainTaskKiller() const { return m_mainTaskKiller; }

			/**
			 * \brief	Gets the const reference to the final main thread task
			 *
			 * \return	The final main thread task.
			 */
			const TaskType& GetFinalMainThreadTask() const { return m_finalMainThreadTask; }

			/**
			 * \brief	Gets the reference to the main task
			 *
			 * \return	The main task.
			 */
			TaskType& GetMainTask() { return m_mainTask; }

			/**
			 * \brief	Gets the reference to the main task killer
			 *
			 * \return	The main task killer.
			 */
			TaskType& GetMainTaskKiller() { return m_mainTaskKiller; }

			/**
			 * \brief	Gets the reference to the final main thread task
			 *
			 * \return	The final main thread task.
			 */
			TaskType& GetFinalMainThreadTask() { return m_finalMainThreadTask; }

			/** \brief	Executes the main task */
			void ExecuteMainTask() const;

			/** \brief	Kill main task */
			void KillMainTask() const;

			/** \brief	Executes the final main thread task */
			void ExecuteFinalMainThreadTask() const;

		private:
			TaskType m_mainTask;
			TaskType m_mainTaskKiller;
			TaskType m_finalMainThreadTask;
		};
	}
}
