#include "DecentSmartServer.h"

#include <thread>

#include <json/json.h>

#include "../Messages.h"
#include "../Common.h"

#include "Server.h"
#include "Connection.h"
#include "ConnectionHandler.h"

DecentSmartServer::DecentSmartServer() :
	m_isTerminated(0)
{
	m_cleanningThread = new std::thread([this]() 
	{
		while (!m_isTerminated)
		{
			std::unique_lock<std::mutex> cleaningLock(m_cleanningMutex);
			//Clean servers:
			while(m_terminatedServers.size() > 0)
			{
				std::pair<std::unique_ptr<Server>, std::thread*> pair(std::move(m_terminatedServers.front()));
				m_terminatedServers.pop();
				pair.second->join();
				delete pair.second;
				pair.first.reset();
			}
			//Clean connections:

			//Done.
			m_cleaningSignal.wait(cleaningLock);
		}
	});
}

DecentSmartServer::~DecentSmartServer()
{
	Terminate();
	m_cleaningSignal.notify_all();
	m_cleanningThread->join();
	delete m_cleanningThread;
	CleanAll();
}

DecentSmartServer::ServerHandle DecentSmartServer::AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler)
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
		while (!serverPtr->IsTerminated())
		{
			std::unique_ptr<Connection> connection = serverPtr->AcceptConnection();
			if (!connection)
			{
				this->AddConnection(connection, handler, JobAtCompletedType());
			}
		}
	});

	m_serverMap.insert(std::make_pair(hdl, std::make_pair(std::move(server), thr)));

	return hdl;
}

void DecentSmartServer::ShutdownServer(ServerHandle handle) noexcept
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

	DecentSmartServer::ServerMapType::iterator it;
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

void DecentSmartServer::AddConnection(std::unique_ptr<Connection>& connection, std::shared_ptr<ConnectionHandler> handler, JobAtCompletedType job)
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

	std::thread* thr = new std::thread([this, hdl, connectionPtr, handler]()
	{
		bool isEnded = false;
		do
		{
			Json::Value jsonRoot;
			try
			{
				connectionPtr->Receive(jsonRoot);
				isEnded = !(handler->ProcessSmartMessage(Messages::ParseCat(jsonRoot), jsonRoot, *connectionPtr));
			}
			catch (const std::exception& e)
			{
				LOGI("Exception Caught when process connection: %s\n", e.what());
				isEnded = true;
			}
			catch (...)
			{
				LOGI("Unknown Exception Caught when process connection.\n");
				isEnded = true;
			}
			
		} while (!isEnded);
	});

	m_connectionMap.insert(std::make_pair(hdl, std::make_pair(std::move(connection), thr)));
}

bool DecentSmartServer::IsTerminated() const noexcept
{
	return m_isTerminated.load();
}

void DecentSmartServer::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}

	std::lock_guard<std::mutex> serverLock(m_serverMapMutex);
	m_isTerminated = 1;

	for (auto it = m_serverMap.begin(); it != m_serverMap.end(); ++it)
	{
		it->second.first->Terminate();
	}
}

void DecentSmartServer::Update()
{
}

void DecentSmartServer::RunUtilUserTerminate()
{
}

void DecentSmartServer::CleanAll() noexcept
{
	std::lock_guard<std::mutex> serverLock(m_serverMapMutex);

	//Clean server Map
	auto it = m_serverMap.begin();
	while (it != m_serverMap.end())
	{
		try
		{
			//Usually will not throw here. Thread should be joinable here.
			it->second.second->join();
		}
		catch (...)
		{
		}

		delete it->second.second;

		it = m_serverMap.erase(it);
	}
}

void DecentSmartServer::AddToCleanQueue(std::pair<std::unique_ptr<Server>, std::thread*> server) noexcept
{
	std::unique_lock<std::mutex> cleaningLock(m_cleanningMutex);

	m_terminatedServers.push(std::move(server));
	m_cleaningSignal.notify_all();
}
