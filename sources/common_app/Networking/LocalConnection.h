#include "Connection.h"

#include <utility>

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

	virtual bool IsTerminate() const;

protected:
	void Terminate();

private:
	LocalConnection(const std::string& sessionId);
	LocalConnection(std::pair<boost::interprocess::shared_memory_object*, boost::interprocess::shared_memory_object*> sharedObjs);
	LocalConnection(boost::interprocess::shared_memory_object* inSharedObj, boost::interprocess::mapped_region* inMapReg, boost::interprocess::shared_memory_object* outSharedObj, boost::interprocess::mapped_region* outMapReg);

private:
	//const std::string m_sessionName;
	boost::interprocess::shared_memory_object* m_inSharedObj;
	boost::interprocess::mapped_region* m_inMapReg;
	LocalSessionStruct& m_inData;
	boost::interprocess::shared_memory_object* m_outSharedObj;
	boost::interprocess::mapped_region* m_outMapReg;
	LocalSessionStruct& m_outData;
};
