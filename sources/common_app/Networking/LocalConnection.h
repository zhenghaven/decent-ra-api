#include "Connection.h"

namespace boost
{
	namespace interprocess
	{
		class shared_memory_object;
		class mapped_region;
	};
};

class LocalAcceptor;
struct LocalSessionStruct;

class LocalConnection : virtual public Connection
{
public:
	static Connection* Connect(const std::string& serverName);

public:
	LocalConnection() = delete;
	LocalConnection(LocalAcceptor& acceptor);
	virtual ~LocalConnection();

	virtual size_t Send(const Messages& msg) override;
	virtual size_t Send(const std::string& msg) override;
	virtual size_t Send(const Json::Value& msg) override;
	virtual size_t Send(const std::vector<uint8_t>& msg) override;
	virtual size_t Send(const void* const dataPtr, const size_t size) override;

	virtual size_t Receive(std::string& msg) override;
	virtual size_t Receive(Json::Value& msg) override;
	virtual size_t Receive(std::vector<uint8_t>& msg) override;

private:
	LocalConnection(const std::string& sessionId);
	LocalConnection(boost::interprocess::shared_memory_object* sharedObj);
	LocalConnection(boost::interprocess::shared_memory_object* sharedObj, boost::interprocess::mapped_region* mapReg);

private:
	//const std::string m_sessionName;
	boost::interprocess::shared_memory_object* m_sharedObj;
	boost::interprocess::mapped_region* m_mapReg;
	LocalSessionStruct* const m_dataPtr;
};
