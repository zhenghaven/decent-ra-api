#include "LocalServer.h"

#include <string>
#include <cstring>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <cppcodec/hex_lower.hpp>

#include "LocalConnectionStructs.h"
#include "LocalConnection.h"

using namespace boost::interprocess;

static std::string GenerateSessionId()
{
	boost::uuids::random_generator randGen;
	boost::uuids::uuid uuid(randGen());

	static_assert(cppcodec::detail::hex<cppcodec::detail::hex_lower>::encoded_size(sizeof(uuid.data)) + 1 == LocalConnectStruct::UUID_STR_LEN,
		"The encoded size must be eqaul to the string length!");

	return cppcodec::hex_lower::encode(uuid.data, sizeof(uuid.data));
}

static inline LocalConnectStruct* OpenAcceptor(const mapped_region& mapReg)
{
	void * addr = mapReg.get_address();
	return new (addr) LocalConnectStruct;
}

static inline shared_memory_object* CreateSharedObj(const std::string & serverName)
{
	shared_memory_object::remove(serverName.c_str());

	shared_memory_object* ptr = new shared_memory_object(create_only, serverName.c_str(), read_write);
	ptr->truncate(sizeof(LocalConnectStruct));
	return ptr;
}

LocalAcceptor::LocalAcceptor(const std::string & serverName) :
	LocalAcceptor(CreateSharedObj(serverName))
{
}

LocalAcceptor::LocalAcceptor(boost::interprocess::shared_memory_object* sharedObj) :
	LocalAcceptor(sharedObj, new mapped_region(*sharedObj, read_write))
{
}

LocalAcceptor::LocalAcceptor(boost::interprocess::shared_memory_object* sharedObj, boost::interprocess::mapped_region* mapReg) :
	//m_serverName(serverName),
	m_sharedObj(sharedObj),
	m_mapReg(mapReg),
	m_connectStruct(OpenAcceptor(*mapReg))
{
}

LocalAcceptor::LocalAcceptor(LocalAcceptor && other) :
	//m_serverName(std::move(other.m_serverName)),
	m_sharedObj(other.m_sharedObj),
	m_mapReg(other.m_mapReg),
	m_connectStruct(other.m_connectStruct)
{
	other.m_sharedObj = nullptr;
	other.m_mapReg = nullptr;
}

LocalAcceptor::~LocalAcceptor()
{
	std::string serverName = m_sharedObj->get_name();

	Terminate();

	delete m_sharedObj;
	delete m_mapReg;

	shared_memory_object::remove(serverName.c_str());
}

bool LocalAcceptor::IsTerminate() const
{
	return m_connectStruct->m_isClosed;
}

void LocalAcceptor::Terminate()
{
	m_connectStruct->m_isClosed = true;

	m_connectStruct->m_idReadySignal.notify_all();
}

boost::interprocess::shared_memory_object* LocalAcceptor::Accept()
{
	scoped_lock<interprocess_mutex> lock(m_connectStruct->m_writeLock);

	m_connectStruct->m_connectSignal.wait(lock,
		[this]() -> bool
	{
		return this->IsTerminate();
	});

	std::string uuid = GenerateSessionId();

	shared_memory_object* sharedObjPtr = new shared_memory_object(create_only, uuid.c_str(), read_write);
	sharedObjPtr->truncate(sizeof(LocalSessionStruct));

	mapped_region mapReg(*sharedObjPtr, read_write);
	LocalSessionStruct* dataPtr = new (mapReg.get_address()) LocalSessionStruct;

	std::memcpy(m_connectStruct->m_msg, uuid.c_str(), sizeof(m_connectStruct->m_msg));
	m_connectStruct->m_idReadySignal.notify_one();

	return sharedObjPtr;
}

LocalServer::LocalServer(const std::string & serverName) :
	m_acceptor(serverName)
{
}

LocalServer::~LocalServer()
{
}

std::unique_ptr<Connection> LocalServer::AcceptConnection()
{
	return std::make_unique<LocalConnection>(m_acceptor);
}
