#pragma once

#include <memory>
#include <functional>
#include <mutex>
#include <map>
#include <atomic>
#include <queue>
#include <condition_variable>

class Server;
class Connection;
class ConnectionHandler;
namespace std
{
	class thread;
}

typedef std::function<void(void)> JobAtCompletedType;

class DecentSmartServer
{
public:
	typedef Server* ServerHandle;
	typedef Connection* ConnectionHandle;

public:
	DecentSmartServer();

	virtual ~DecentSmartServer();

	//Thread safe
	virtual ServerHandle AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler);
	//Thread safe
	virtual void ShutdownServer(ServerHandle handle) noexcept;

	//Thread safe.
	virtual void AddConnection(std::unique_ptr<Connection>& connection, std::shared_ptr<ConnectionHandler> handler, JobAtCompletedType job);

	virtual bool IsTerminated() const noexcept;

	//Thread safe
	virtual void Terminate() noexcept;

	virtual void Update();

	virtual void RunUtilUserTerminate();

private:
	typedef std::map<ServerHandle, std::pair<std::unique_ptr<Server>, std::thread*> > ServerMapType;
	typedef std::map<ConnectionHandle, std::pair<std::unique_ptr<Connection>, std::thread*> > ConnectionMapType;

	std::mutex m_serverMapMutex;
	ServerMapType m_serverMap;

	std::mutex m_connectionMapMutex;
	ConnectionMapType m_connectionMap;

	std::mutex m_cleanningMutex;
	std::condition_variable m_cleaningSignal;
	std::queue<std::pair<std::unique_ptr<Server>, std::thread*> > m_terminatedServers;
	std::queue<std::pair<std::unique_ptr<Connection>, std::thread*> > m_terminatedConnections;

	std::mutex m_mainThrJobMutex;
	std::queue<JobAtCompletedType> m_mainThreadJob;

	std::thread* m_cleanningThread;

	std::atomic<uint8_t> m_isTerminated;

	void CleanAll() noexcept;
	void AddToCleanQueue(std::pair<std::unique_ptr<Server>, std::thread*> server) noexcept;
	void AddToCleanQueue(std::pair<std::unique_ptr<Connection>, std::thread*> server) noexcept;
};
