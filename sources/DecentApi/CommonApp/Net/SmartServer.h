#pragma once

#include <set>
#include <memory>
#include <tuple>
#include <queue>
#include <condition_variable>

#include "../Threading/ThreadPool.h"
#include "../Threading/SingleTaskThreadPool.h"

namespace Decent
{
	namespace Threading
	{
		class MainThreadAsynWorker;
	}

	namespace Net
	{
		class Server;
		class ConnectionBase;
		class ConnectionHandler;
		class ConnectionPoolBase;

		class SmartServer
		{
		public: //static members:
			typedef Server* ServerHandle;

		public:
			SmartServer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	mainThreadWorker	The main thread worker. The main thread worker should be
			 * 										declared in main() function, and stay alive until the program
			 * 										is terminated.
			 * \param 		  	acceptRetry			(Optional) number of retries before shutdown the server.
			 * 										If the server *continuously* failed to accept connection for
			 * 										'acceptRetry' times, the server will be automatically
			 * 										shutdown.
			 */
			SmartServer(std::shared_ptr<Threading::MainThreadAsynWorker> mainThreadWorker, const size_t acceptRetry = 10);

			SmartServer(const SmartServer&) = delete;

			SmartServer(SmartServer&&) = delete;
			
			/** \brief	Destructor. Terminate will be called here. */
			virtual ~SmartServer();

			/**
			 * \brief	Adds a server. A new thread will be created to accept the connection.
			 *
			 * \param [in,out]	server			 	The server.
			 * \param 		  	handler			 	The handler for the incoming connections.
			 * \param 		  	cntPool			 	(Optional) The connection pool. If null, connection will be closed once it is done.
			 * \param 		  	threadNum		 	The number of threads for this server.
			 * \param 		  	cntPoolWorkerSize	The number of workers to hold the idle connections.
			 *
			 * \return	A ServerHandle, which can be used to shutdown the server later.
			 */
			virtual ServerHandle AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler, std::shared_ptr<ConnectionPoolBase> cntPool, size_t threadNum, size_t cntPoolWorkerSize);

			/**
			 * \brief	Shutdown the specified server. However, the connection that created by this server is
			 * 			not guaranteed to be terminated. This is determined by the implementation of the
			 * 			Server::Terminate function.
			 *
			 * \param	handle	The server handle.
			 */
			virtual void ShutdownServer(ServerHandle handle);

			/**
			 * \brief	Adds a connection to the thread pool. A processor for this connection will be
			 * 			created. The processor will be tried to add to the thread pool first. However, if all
			 * 			workers are busy, it will be added to the single task thread pool.
			 *
			 * \param [in,out]	connection	The connection. The ownership of the connection will be transferred to the worker.
			 * \param 		  	handler   	The handler for the connection.
			 */
			virtual void AddConnection(std::unique_ptr<ConnectionBase>& connection, std::shared_ptr<ConnectionHandler> handler,
				std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<Threading::ThreadPool> cntPoolWorkerPool, std::shared_ptr<Threading::ThreadPool> thrPool);

			/**
			 * \brief	Query if this smart server is terminated
			 *
			 * \return	True if terminated, false if not.
			 */
			virtual bool IsTerminated() const noexcept;

			/** \brief	Terminates this smart server */
			void Terminate() noexcept;

			/**
			 * \brief	Gets maximum number of retries to accept connections.
			 *
			 * \return	The maximum number of retries to accept connections.
			 */
			size_t GetMaxAcceptRetry() const { return m_acceptRetry; }

		protected:
			virtual void AddConnection(std::shared_ptr<ConnectionBase> connection, std::shared_ptr<ConnectionHandler> handler,
				std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<Threading::ThreadPool> cntPoolWorkerPool, std::shared_ptr<Threading::ThreadPool> thrPool);

			/** \brief	Worker that keeps accepting connection. */
			virtual void AcceptConnectionWorker(ServerHandle handle, std::shared_ptr<Server> server, std::shared_ptr<ConnectionHandler> handler, 
				std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<Threading::ThreadPool> cntPoolWorkerPool, std::shared_ptr<Threading::ThreadPool> thrPool);

			/** \brief	Server cleaner, who cleans the server that has already been shutdown-ed. */
			virtual void ServerCleaner();

			virtual void ConnectionProcesser(std::shared_ptr<ConnectionBase> connection, std::shared_ptr<ConnectionHandler> handler,
				std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<Threading::ThreadPool> cntPoolWorkerPool, std::shared_ptr<Threading::ThreadPool> thrPool) noexcept;

			virtual void ConnectionPoolWorker(std::shared_ptr<ConnectionBase> connection, std::shared_ptr<ConnectionHandler> handler,
				std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<Threading::ThreadPool> cntPoolWorkerPool, std::shared_ptr<Threading::ThreadPool> thrPool);

		private:
			const size_t m_acceptRetry;

			std::weak_ptr<Threading::MainThreadAsynWorker> m_mainThreadWorker;

			std::vector<std::unique_ptr<std::thread> > m_cleanerPool;

			std::atomic<bool> m_isTerminated;

			Threading::SingleTaskThreadPool m_singleTaskPool;

			std::mutex m_serverMapMutex;
			std::map<ServerHandle, std::shared_ptr<Server> > m_serverMap;

			std::mutex m_serverCleanQueueMutex;
			std::queue<ServerHandle> m_serverCleanQueue;
			std::condition_variable m_serverCleanSignal;

			std::mutex m_heldCntListMutex;
			std::map<ConnectionBase*, std::shared_ptr<ConnectionBase> > m_heldCntList;
			std::set<ConnectionBase*> m_earlyFreedCnt;
		};
	}
}
