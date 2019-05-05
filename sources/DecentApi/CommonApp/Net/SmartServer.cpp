#include "SmartServer.h"

#include <json/json.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Net/ConnectionPoolBase.h"

#include "../Threading/TaskSet.h"

#include "NetworkException.h"
#include "Server.h"
#include "Connection.h"
#include "SmartMessages.h"
#include "ConnectionHandler.h"

using namespace Decent::Net;
using namespace Decent::Threading;

void SmartServer::AcceptConnectionWorker(ServerHandle handle, std::shared_ptr<Server> server, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> thrPool)
{
	size_t retried = 0;
	while (!server->IsTerminated() && retried < m_acceptRetry)
	{
		try
		{
			std::unique_ptr<Connection> connection = server->AcceptConnection();
			this->AddConnection(connection, handler, cntPool, thrPool);
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

SmartServer::SmartServer(const size_t minThreadPoolSize, MainThreadAsynWorker & mainThreadWorker, const size_t acceptRetry) :
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

SmartServer::ServerHandle SmartServer::AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler, std::shared_ptr<ConnectionPoolBase> cntPool, size_t threadNum)
{
	std::shared_ptr<Server> sharedServer(std::move(server));
	ServerHandle serverhandle = sharedServer.get();

	std::shared_ptr<ThreadPool> thrPool = std::make_shared<ThreadPool>(threadNum, m_mainThreadWorker);

	std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
		[this, serverhandle, sharedServer, handler, cntPool, thrPool]() //Main task
	{
		this->AcceptConnectionWorker(serverhandle, sharedServer, handler, cntPool, thrPool);
	},
		[sharedServer, thrPool]() //Main task killer
	{
		sharedServer->Terminate();
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

void SmartServer::AddConnection(std::unique_ptr<Connection>& connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> thrPool)
{
	std::shared_ptr<Connection> sharedCnt(std::move(connection));

	this->AddConnection(sharedCnt, handler, cntPool, thrPool);
}

void SmartServer::AddConnection(std::shared_ptr<Connection> connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> thrPool)
{
	std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
		[this, connection, handler, cntPool, thrPool]() //Main task
	{
		this->ConnectionProcesser(connection, handler, cntPool, thrPool);
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

void SmartServer::ConnectionProcesser(std::shared_ptr<Connection> connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> thrPool) noexcept
{
	try
	{
		Json::Value jsonRoot;
		std::string categoryStr;
		connection->ReceivePack(categoryStr);
		categoryStr.erase(std::find(categoryStr.begin(), categoryStr.end(), '\0'), categoryStr.end());
		handler->ProcessSmartMessage(categoryStr, jsonRoot, *connection);

		//Msg processing is done.
		
		std::unique_ptr<TaskSet> task = std::make_unique<TaskSet>(
			[this, connection, handler, cntPool, thrPool]() //Main task
		{
			this->ConnectionPoolWorker(connection, handler, cntPool, thrPool);
		},
			[connection]() //Main task killer
		{
			connection->Terminate();
		}
		);

		m_singleTaskPool.AddTaskSet(task);
	}
	catch (const Decent::Net::ConnectionClosedException&)
	{
		//Connection is closed.
		return;
	}
	catch (const Decent::Net::Exception& e)
	{
		const char* msg = e.what();
		LOGI("SmartServer: Network Exception Caught:");
		LOGI("%s", msg);
		LOGI("Connection will be closed.");
		return;
	}
	catch (const std::exception& e)
	{
		const char* msg = e.what();
		LOGI("SmartServer: Exception Caught:");
		LOGI("%s", msg);
		LOGI("Connection will be closed.");
		return;
	}
	catch (...)
	{
		LOGI("SmartServer: Unknown Exception Caught when process connection.");
		LOGI("Connection will be closed.");
		return;
	}
}

void SmartServer::ConnectionPoolWorker(std::shared_ptr<Connection> connection, std::shared_ptr<ConnectionHandler> handler,
	std::shared_ptr<ConnectionPoolBase> cntPool, std::shared_ptr<ThreadPool> thrPool)
{
	try
	{
		if (!cntPool->HoldInComingConnection(*connection))
		{
			//connection is terminated
			return;
		}
		//Connection has been waken up
		this->AddConnection(connection, handler, cntPool, thrPool);
	}
	catch (const std::exception&)
	{
		return;
	}
}
