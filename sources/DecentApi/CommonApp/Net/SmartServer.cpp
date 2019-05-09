#include "SmartServer.h"

#include <json/json.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Net/ConnectionPoolBase.h"
#include "../../Common/Net/ConnectionBase.h"
#include "../../Common/Net/ConnectionHandler.h"

#include "../Threading/TaskSet.h"

#include "NetworkException.h"
#include "Server.h"

using namespace Decent::Net;
using namespace Decent::Threading;

void SmartServer::AcceptConnectionWorker(ServerHandle handle, std::shared_ptr<Server> server, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> cntPoolWorkerPool, std::shared_ptr<ThreadPool> thrPool)
{
	size_t retried = 0;
	while (!m_isTerminated && !server->IsTerminated() && retried < m_acceptRetry)
	{
		try
		{
			std::unique_ptr<ConnectionBase> connection = server->AcceptConnection();
			this->AddConnection(connection, handler, cntPool, cntPoolWorkerPool, thrPool);
			retried = 0;
		}
		catch (const Decent::Net::ConnectionClosedException&)
		{
			//Server has been shutdown-ed.
			retried = m_acceptRetry; //Just make sure is going to shutdown
		}
		catch (const Decent::Net::Exception& e)
		{
			const char* msg = e.what();
			LOGI("SmartServer: Network Exception Caught:");
			LOGI("%s", msg);
			++retried;
		}
	}

	std::unique_lock<std::mutex> serverCleanQueueLock(m_serverCleanQueueMutex);
	m_serverCleanQueue.push(handle);
	serverCleanQueueLock.unlock();
	m_serverCleanSignal.notify_one();
}

SmartServer::SmartServer(std::shared_ptr<MainThreadAsynWorker> mainThreadWorker, const size_t acceptRetry) :
	m_acceptRetry(acceptRetry),
	m_mainThreadWorker(mainThreadWorker),
	m_cleanerPool(),
	m_isTerminated(false),
	m_singleTaskPool(mainThreadWorker, 2)
{
	for (size_t i = 0; i < 1; ++i)
	{
		std::unique_ptr<std::thread> thr = Tools::make_unique<std::thread>(
			[this]() {
			this->ServerCleaner();
		});

		m_cleanerPool.push_back(std::move(thr));
	}
}

SmartServer::~SmartServer()
{
	Terminate();
}

SmartServer::ServerHandle SmartServer::AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler, std::shared_ptr<ConnectionPoolBase> cntPool, size_t threadNum, size_t cntPoolWorkerSize)
{
	std::shared_ptr<Server> sharedServer(std::move(server));
	ServerHandle serverhandle = sharedServer.get();

	std::shared_ptr<ThreadPool> thrPool = std::make_shared<ThreadPool>(threadNum, m_mainThreadWorker.expired() ? nullptr : m_mainThreadWorker.lock());
	std::shared_ptr<ThreadPool> cntPoolWorkerPool = std::make_shared<ThreadPool>(cntPoolWorkerSize, m_mainThreadWorker.expired() ? nullptr : m_mainThreadWorker.lock());

	std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
		[this, serverhandle, sharedServer, handler, cntPool, cntPoolWorkerPool, thrPool]() //Main task
	{
		this->AcceptConnectionWorker(serverhandle, sharedServer, handler, cntPool, cntPoolWorkerPool, thrPool);
	},
		[sharedServer, cntPoolWorkerPool, thrPool]() //Main task killer
	{
		sharedServer->Terminate();
		cntPoolWorkerPool->Terminate();
		thrPool->Terminate();
	}
	);

	m_singleTaskPool.AddTaskSet(task);

	m_serverMap.insert(std::make_pair(serverhandle, sharedServer));

	return serverhandle;
}

void SmartServer::ShutdownServer(ServerHandle handle)
{
	std::unique_lock<std::mutex> serverMapLock(m_serverMapMutex);
	auto it = m_serverMap.find(handle);
	if (it != m_serverMap.end())
	{
		it->second->Terminate();
	}
}

void SmartServer::AddConnection(std::unique_ptr<ConnectionBase>& connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> cntPoolWorkerPool, std::shared_ptr<ThreadPool> thrPool)
{
	std::shared_ptr<ConnectionBase> sharedCnt(std::move(connection));

	this->AddConnection(sharedCnt, handler, cntPool, cntPoolWorkerPool, thrPool);
}

void SmartServer::AddConnection(std::shared_ptr<ConnectionBase> connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> cntPoolWorkerPool, std::shared_ptr<ThreadPool> thrPool)
{
	if (m_isTerminated)
	{
		return;
	}

	std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
		[this, connection, handler, cntPool, cntPoolWorkerPool, thrPool]() //Main task
	{
		this->ConnectionProcesser(connection, handler, cntPool, cntPoolWorkerPool, thrPool);
	},
		[connection]() //Main task killer
	{
		connection->Terminate();
	}
	);

	thrPool->AddTaskSet(task);
}

bool SmartServer::IsTerminated() const noexcept
{
	return m_isTerminated;
}

void SmartServer::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}

	m_isTerminated = true;

	try
	{

		std::unique_lock<std::mutex> heldCntListLock(m_heldCntListMutex);
		m_heldCntList.clear();
	}
	catch (...) {}

	m_singleTaskPool.Terminate();

	try
	{
		m_serverCleanSignal.notify_all();
		for (std::unique_ptr<std::thread>& thr : m_cleanerPool)
		{
			try { thr->join(); } catch (const std::exception&) {}
		}
	} catch (const std::exception&) {}
}

void SmartServer::ServerCleaner()
{
	std::queue<ServerHandle> localCleanQueue;

	while (!m_isTerminated)
	{
		{
			std::unique_lock<std::mutex> cleanQueueLock(m_serverCleanQueueMutex);
			m_serverCleanSignal.wait(cleanQueueLock, [this]() {
				return m_isTerminated || m_serverCleanQueue.size() > 0;
			});

			if (m_isTerminated)
			{
				return;
			}

			localCleanQueue.swap(m_serverCleanQueue);
		}

		std::unique_lock<std::mutex> serverMapLock(m_serverMapMutex);
		while (localCleanQueue.size() > 0)
		{
			auto it = m_serverMap.find(localCleanQueue.front());
			if (it != m_serverMap.end())
			{
				m_serverMap.erase(it);
			}
			localCleanQueue.pop();
		}
	}
}

void SmartServer::ConnectionProcesser(std::shared_ptr<ConnectionBase> connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> cntPoolWorkerPool, std::shared_ptr<ThreadPool> thrPool) noexcept
{
	try
	{
		std::string categoryStr;
		connection->ReceivePack(categoryStr);
		categoryStr.erase(std::find(categoryStr.begin(), categoryStr.end(), '\0'), categoryStr.end());

		ConnectionBase* prevHeldCnt = nullptr;

		bool holdConnection = handler->ProcessSmartMessage(categoryStr, *connection, prevHeldCnt);

		//Msg processing is done.
		
		if (holdConnection)
		{
			//Client connection need to be held.
			if (!m_isTerminated)
			{
				std::unique_lock<std::mutex> heldCntListLock(m_heldCntListMutex);
				auto earlyIt = m_earlyFreedCnt.find(connection.get());
				if (earlyIt != m_earlyFreedCnt.end())
				{
					m_earlyFreedCnt.erase(earlyIt);
					holdConnection = false;
				}
				else
				{
					m_heldCntList[connection.get()] = std::move(connection);
				}
			}
		}

		if(!holdConnection)
		{
			//Client connection is now free.
			std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
				[this, connection, handler, cntPool, cntPoolWorkerPool, thrPool]() //Main task
			{
				this->ConnectionPoolWorker(connection, handler, cntPool, cntPoolWorkerPool, thrPool);
			},
				[connection]() //Main task killer
			{
				connection->Terminate();
			}
			);

			cntPoolWorkerPool->AddTaskSet(task);
		}

		if (prevHeldCnt)
		{
			//previous held connection need to be freed.
			
			std::shared_ptr<ConnectionBase> freeCnt;
			{
				std::unique_lock<std::mutex> heldCntListLock(m_heldCntListMutex);
				auto it = m_heldCntList.find(prevHeldCnt);
				if (it != m_heldCntList.end())
				{
					freeCnt = it->second;
				}
				else
				{
					m_earlyFreedCnt.insert(prevHeldCnt);
				}
			}

			if (freeCnt)
			{
				std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
					[this, freeCnt, handler, cntPool, cntPoolWorkerPool, thrPool]() //Main task
				{
					this->ConnectionPoolWorker(freeCnt, handler, cntPool, cntPoolWorkerPool, thrPool);
				},
					[freeCnt]() //Main task killer
				{
					freeCnt->Terminate();
				}
				);

				cntPoolWorkerPool->AddTaskSet(task);
			}
		}
		
	}
	catch (const Decent::Net::ConnectionClosedException&)
	{
		//Connection is closed.
		return;
	}
	catch (const Decent::Net::Exception& e)
	{
		const char* msg = e.what();
		PRINT_I("Exception Caught in SmartServer::ConnectionProcesser. Error Msg %s.", e.what());
		LOGI("Connection will be closed.");
		return;
	}
	catch (const std::exception& e)
	{
		const char* msg = e.what();
		PRINT_I("Exception Caught in SmartServer::ConnectionProcesser. Error Msg %s.", e.what());
		LOGI("Connection will be closed.");
		return;
	}
	catch (...)
	{
		PRINT_I("Unknown Exception Caught in SmartServer::ConnectionProcesser.");
		LOGI("Connection will be closed.");
		return;
	}
}

void SmartServer::ConnectionPoolWorker(std::shared_ptr<ConnectionBase> connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> cntPoolWorkerPool, std::shared_ptr<ThreadPool> thrPool)
{
	try
	{
		if (!cntPool || !cntPool->HoldInComingConnection(*connection))
		{
			//Connection pool is not given, or, connection is terminated by peer.
			return;
		}
		//Connection has been waken up
		this->AddConnection(connection, handler, cntPool, cntPoolWorkerPool, thrPool);
	}
	catch (const std::exception&)
	{
		return;
	}
}
