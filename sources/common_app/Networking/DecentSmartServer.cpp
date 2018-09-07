#include "DecentSmartServer.h"


#include "Server.h"
#include "Connection.h"

DecentSmartServer::DecentSmartServer() :
	m_isTerminated(0),
	m_threadId(std::this_thread::get_id())
{
}

DecentSmartServer::~DecentSmartServer()
{
	Terminate();
}

DecentSmartServer::ServerHandle DecentSmartServer::AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler)
{
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
				this->AddConnection(connection, handler, []() {});
			}
		}
	});

	m_serverMap.insert(std::make_pair(hdl, std::make_pair(std::move(server), thr)));

	return ServerHandle();
}

void DecentSmartServer::ShutdownServer(ServerHandle handle) noexcept
{
	//Safty check. make sure this function is called on the main thread.
	if (m_threadId != std::this_thread::get_id())
	{
		return;
	}

	DecentSmartServer::ServerMapType::iterator it;
	try
	{
		it = m_serverMap.find(handle); //Usually will not throw
	}
	catch (...)
	{
		return;
	}

	if (it == m_serverMap.end())
	{
		return;
	}

	ShutdownServer(it);
}

void DecentSmartServer::AddConnection(std::unique_ptr<Connection>& connection, std::shared_ptr<ConnectionHandler> handler, JobAtCompletedType job)
{
}

void DecentSmartServer::Terminate() noexcept
{
	auto it = m_serverMap.begin();

	while (it != m_serverMap.end())
	{
		it = ShutdownServer(it);
	}
}

DecentSmartServer::ServerMapType::iterator DecentSmartServer::ShutdownServer(ServerMapType::iterator it) noexcept
{
	it->second.first->Terminate(); //noexcept
	try
	{
		//Usually will not throw here. Thread should be joinable here.
		it->second.second->join();
	}
	catch (...)
	{
	}
	
	delete it->second.second;

	return m_serverMap.erase(it); //noexcept
}
