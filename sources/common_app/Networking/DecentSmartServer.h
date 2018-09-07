#pragma once

#include <memory>
#include <functional>
#include <mutex>
#include <map>
#include <thread>
#include <atomic>

class Server;
class Connection;
class ConnectionHandler;
//namespace std
//{
//	class thread;
//}

typedef std::function<void(void)> JobAtCompletedType;

class DecentSmartServer
{
public:
	typedef Server* ServerHandle;

public:
	DecentSmartServer();

	virtual ~DecentSmartServer();

	//Not thread safe, call it on main thread.
	virtual ServerHandle AddServer(std::unique_ptr<Server>& server, std::shared_ptr<ConnectionHandler> handler);
	//Not thread safe, call it on main thread.
	virtual void ShutdownServer(ServerHandle handle) noexcept;

	//Thread safe.
	virtual void AddConnection(std::unique_ptr<Connection>& connection, std::shared_ptr<ConnectionHandler> handler, JobAtCompletedType job);

	//Not thread safe, call it on main thread.
	virtual void Terminate() noexcept;

private:
	typedef std::map<ServerHandle, std::pair<std::unique_ptr<Server>, std::thread*> > ServerMapType;
	ServerMapType m_serverMap;

	ServerMapType::iterator ShutdownServer(ServerMapType::iterator it) noexcept;

	std::atomic<uint8_t> m_isTerminated;
	const std::thread::id m_threadId;
};
