#include "SmartServer.h"

#include <thread>

#include <boost/asio/signal_set.hpp>
#include <boost/asio/io_service.hpp>
#include <json/json.h>

#include "../../Common/Common.h"
#include "../../Common/Net/NetworkException.h"

#include "Server.h"
#include "Connection.h"
#include "SmartMessages.h"
#include "ConnectionHandler.h"

using namespace Decent::Net;

SmartServer::SmartServer(const size_t acceptRetry) :
	m_isTerminated(0),
	m_acceptRetry(acceptRetry)
{
	m_cleanningThread = new std::thread([this]() 
	{
		while (!m_isTerminated)
		{
			std::unique_lock<std::mutex> cleaningLock(m_cleanningMutex);
			//Clean servers:
			while(m_terminatedServers.size() > 0)
			{
				m_terminatedServers.front().second->join();
				delete m_terminatedServers.front().second;
				m_terminatedServers.front().first.reset();
				m_terminatedServers.pop();
			}
			//Clean connections:
			{
				std::unique_lock<std::mutex> connectionLock(m_connectionMapMutex);
				while (m_terminatedConnections.size() > 0)
				{
					auto it = m_connectionMap.find(m_terminatedConnections.front());
					if (it != m_connectionMap.end())
					{
						it->second.second->join();
						delete it->second.second;
						m_connectionMap.erase(it);
					}
					m_terminatedConnections.pop();
				}
			}
			//Done.
			if (!m_isTerminated)
			{
				m_cleaningSignal.wait(cleaningLock);
			}
		}
	});
}

SmartServer::~SmartServer()
{
	Terminate();
	CleanAll();
	m_cleaningSignal.notify_all();
	m_cleanningThread->join();
	delete m_cleanningThread;
}

SmartServer::ServerHandle SmartServer::AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler)
{
	if (m_isTerminated)
	{
		return nullptr;
	}
	std::lock_guard<std::mutex> serverLock(m_serverMapMutex);
	if (m_isTerminated)
	{
		return nullptr;
	}

	if (!server ||
		m_serverMap.find(server.get()) != m_serverMap.end()) //Usually this case will not happened.
	{
		return nullptr;
	}

	ServerHandle hdl = server.get();
	Server* serverPtr = server.get();

	std::thread* thr = new std::thread([this, serverPtr, handler]()
	{
		size_t retried = 0;
		while (!serverPtr->IsTerminated() && retried < m_acceptRetry)
		{
			try
			{
				std::unique_ptr<Connection> connection = serverPtr->AcceptConnection();
				this->AddConnection(connection, handler, JobAtCompletedType(), JobAtCompletedType());
				retried = 0;
			}
			catch (const Decent::Net::Exception& e)
			{
				const char* msg = e.what();
				LOGI("SmartServer: Network Exception Caught:");
				LOGI("%s", msg);
				++retried;
			}
		}
	});

	m_serverMap.insert(std::make_pair(hdl, std::make_pair(std::move(server), thr)));

	return hdl;
}

void SmartServer::ShutdownServer(ServerHandle handle) noexcept
{
	if (m_isTerminated)
	{
		return;
	}
	std::lock_guard<std::mutex> serverLock(m_serverMapMutex);
	if (m_isTerminated)
	{
		return;
	}

	SmartServer::ServerMapType::iterator it;
	try
	{
		it = m_serverMap.find(handle); //Usually will not throw here, since we are using standard compare func.
	}
	catch (...)
	{
		return;
	}

	if (it != m_serverMap.end())
	{
		it->second.first->Terminate();
		AddToCleanQueue(std::make_pair(std::move(it->second.first), it->second.second));
		
		m_serverMap.erase(it);
	}
}

void SmartServer::AddConnection(std::unique_ptr<Connection>& connection, std::shared_ptr<ConnectionHandler> handler, JobAtCompletedType sameThrJob, JobAtCompletedType mainThrJob)
{
	if (m_isTerminated)
	{
		return;
	}
	std::lock_guard<std::mutex> connectionLock(m_connectionMapMutex);
	if (m_isTerminated)
	{
		return;
	}

	if (!connection ||
		m_connectionMap.find(connection.get()) != m_connectionMap.end()) //Usually this case will not happened.
	{
		return;
	}

	ConnectionHandle hdl = connection.get();
	Connection* connectionPtr = connection.get();

	std::thread* thr = new std::thread([this, hdl, connectionPtr, handler, sameThrJob, mainThrJob]()
	{
		bool isEnded = false;
		do
		{
			Json::Value jsonRoot;
			try
			{
				connectionPtr->ReceivePack(jsonRoot);
				isEnded = !(handler->ProcessSmartMessage(SmartMessages::ParseCat(jsonRoot), jsonRoot, *connectionPtr));
			}
			catch (const Decent::Net::Exception& e)
			{
				const char* msg = e.what();
				LOGI("SmartServer: Network Exception Caught:");
				LOGI("%s", msg);
				LOGI("Connection will be closed.");
				isEnded = true;
			}
			catch (const std::exception& e)
			{
				const char* msg = e.what();
				LOGI("SmartServer: Exception Caught:");
				LOGI("%s", msg);
				LOGI("Connection will be closed.");
				isEnded = true;
			}
			catch (...)
			{
				LOGI("SmartServer: Unknown Exception Caught when process connection.");
				LOGI("Connection will be closed.");
				isEnded = true;
			}
			
		} while (!isEnded);

		connectionPtr->Terminate();

		if (sameThrJob)
		{
			sameThrJob();
		}
		if (mainThrJob)
		{
			AddMainThreadJob(mainThrJob);
		}

		AddToCleanQueue(hdl);
	});

	m_connectionMap.insert(std::make_pair(hdl, std::make_pair(std::move(connection), thr)));
}

bool SmartServer::IsTerminated() const noexcept
{
	return m_isTerminated.load();
}

void SmartServer::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}

	std::unique_lock<std::mutex> serverLock(m_serverMapMutex, std::defer_lock);
	std::unique_lock<std::mutex> connectionLock(m_connectionMapMutex, std::defer_lock);
	std::lock(serverLock, connectionLock);

	m_isTerminated = 1;

	for (auto it = m_serverMap.begin(); it != m_serverMap.end(); ++it)
	{
		it->second.first->Terminate();
	}
	for (auto it = m_connectionMap.begin(); it != m_connectionMap.end(); ++it)
	{
		it->second.first->Terminate();
	}

	m_mainThrSignal.notify_all();
}

void SmartServer::Update()
{
	if (m_isTerminated)
	{
		return;
	}

	std::unique_lock<std::mutex> mainThrJobLock(m_mainThrJobMutex);
	RunMainThrJobs();
}

void SmartServer::RunUtilUserTerminate()
{
	boost::asio::io_service io_service;

	std::thread* intSignalThread = new std::thread([this, &io_service]()
	{
		boost::asio::signal_set signals(io_service, SIGINT);
		signals.async_wait([this](const boost::system::error_code& error, int signal_number)
		{
			Terminate();
		});

		io_service.run();
	});

	{
		std::unique_lock<std::mutex> mainThrJobLock(m_mainThrJobMutex);
		while (!m_isTerminated)
		{
			RunMainThrJobs();
			m_mainThrSignal.wait(mainThrJobLock);
		}
		if (!io_service.stopped())
		{
			io_service.stop();
		}
	}

	intSignalThread->join();
	delete intSignalThread;
}

void SmartServer::CleanAll() noexcept
{
	std::unique_lock<std::mutex> serverLock(m_serverMapMutex, std::defer_lock);
	std::unique_lock<std::mutex> connectionLock(m_connectionMapMutex, std::defer_lock);
	std::lock(serverLock, connectionLock);

	//Clean server Map
	auto its = m_serverMap.begin();
	while (its != m_serverMap.end())
	{
		try
		{
			//Usually will not throw here. Thread should be joinable here.
			its->second.second->join();
		}
		catch (...)
		{}

		delete its->second.second;

		its = m_serverMap.erase(its);
	}
	//Clean connection Map
	auto itc = m_connectionMap.begin();
	while (itc != m_connectionMap.end())
	{
		try
		{
			//Usually will not throw here. Thread should be joinable here.
			itc->second.second->join();
		}
		catch (...)
		{}

		delete itc->second.second;

		itc = m_connectionMap.erase(itc);
	}
}

void SmartServer::AddToCleanQueue(std::pair<std::unique_ptr<Server>, std::thread*> server) noexcept
{
	std::unique_lock<std::mutex> cleaningLock(m_cleanningMutex);

	m_terminatedServers.push(std::move(server));
	m_cleaningSignal.notify_all();
}

void SmartServer::AddToCleanQueue(ConnectionHandle connection) noexcept
{
	if (!connection)
	{
		return;
	}

	std::unique_lock<std::mutex> cleaningLock(m_cleanningMutex);

	m_terminatedConnections.push(connection);
	m_cleaningSignal.notify_all();
}

void SmartServer::AddMainThreadJob(JobAtCompletedType mainThrJob)
{
	std::unique_lock<std::mutex> mainThrJobLock(m_mainThrJobMutex);

	m_mainThreadJob.push(mainThrJob);
	m_mainThrSignal.notify_all();
}

void SmartServer::RunMainThrJobs()
{
	while (m_mainThreadJob.size() > 0)
	{
		if (m_mainThreadJob.front())
		{
			m_mainThreadJob.front()();
		}
		m_mainThreadJob.pop();
	}
}
