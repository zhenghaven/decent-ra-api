#include "Connection.h"

#include <memory>
#include <utility>

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

class LocalAcceptor;
struct LocalSessionStruct;

class LocalConnection : virtual public Connection
{
public:
	static Connection* Connect(const std::string& serverName);

public:
	LocalConnection() = delete;
	LocalConnection(LocalAcceptor& acceptor);
	LocalConnection(const LocalConnection& other) = delete;
	LocalConnection(LocalConnection&& other);
	virtual ~LocalConnection();

	LocalConnection& operator=(const LocalConnection& other) = delete;
	LocalConnection& operator=(LocalConnection&& other);

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
	LocalConnection(const std::pair<std::shared_ptr<SharedObject<LocalSessionStruct> >, std::shared_ptr<SharedObject<LocalSessionStruct> > >& sharedObjs);

private:
	std::shared_ptr<SharedObject<LocalSessionStruct> > m_inSharedObj;
	std::shared_ptr<SharedObject<LocalSessionStruct> > m_outSharedObj;
};
