#include "Server.h"

#include <string>
#include <utility>
#include <memory>

namespace boost
{
	namespace interprocess
	{
		class shared_memory_object;
		class mapped_region;
	};
};

template<typename T>
struct SharedObject;

struct LocalConnectStruct;
struct LocalSessionStruct;

class LocalAcceptor
{
public:
	LocalAcceptor() = delete;
	LocalAcceptor(const std::string& serverName);
	LocalAcceptor(const LocalAcceptor& other) = delete; //Copy is not allowed.
	//LocalAcceptor(LocalAcceptor&& other);
	virtual ~LocalAcceptor();

	bool IsTerminate() const;

	std::pair<std::shared_ptr<SharedObject<LocalSessionStruct> >,
		std::shared_ptr<SharedObject<LocalSessionStruct> > > Accept();

protected:
	void Terminate();

private:
	//LocalAcceptor(boost::interprocess::shared_memory_object* sharedObj);
	//LocalAcceptor(boost::interprocess::shared_memory_object* sharedObj, boost::interprocess::mapped_region* mapReg);

private:
	//const std::string m_serverName;
	//boost::interprocess::shared_memory_object* m_sharedObj;
	//boost::interprocess::mapped_region* m_mapReg;
	//LocalConnectStruct* const m_connectStruct;
	std::shared_ptr<SharedObject<LocalConnectStruct> > m_sharedObj;
};

class LocalServer : virtual public Server
{
public:
	LocalServer() = delete;
	LocalServer(const std::string& serverName);
	LocalServer(const LocalServer& other) = delete; //Copy is not allowed.
	//LocalServer(LocalServer&& other);
	virtual ~LocalServer();

	virtual std::unique_ptr<Connection> AcceptConnection() override;

private:
	LocalAcceptor m_acceptor;
};
