#include "Server.h"

#include <string>

#include <boost/interprocess/managed_shared_memory.hpp>

#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>

//#include <boost/uuid/uuid.hpp>

struct LocalConnectStruct
{
	enum { UUID_SIZE = 16 };
	boost::interprocess::interprocess_mutex m_connectLock;
	boost::interprocess::interprocess_condition m_connectSignal;

	uint8_t m_msg[UUID_SIZE];
};

struct LocalSessionStruct
{
	enum { MSG_SIZE = 65536 };
	boost::interprocess::interprocess_mutex m_msgLock;
	boost::interprocess::interprocess_condition m_msgSignal;

	uint8_t m_msg[MSG_SIZE];
};

class LocalServer : public Server
{
public:
	LocalServer() = delete;
	LocalServer(const std::string& serverName);
	virtual ~LocalServer();

private:
	boost::interprocess::managed_shared_memory
};
