#include "LocalServer.h"

#include <string>
#include <cstring>
#include <atomic>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <cppcodec/hex_lower.hpp>

#include "LocalConnectionStructs.h"
#include "LocalConnection.h"
#include "NetworkException.h"

using namespace boost::interprocess;

#define ACCEPTOR_CLOSED_CHECK if (m_connectStruct->IsClosed())\
								 {\
								 throw ConnectionClosedException();\
								 }

static std::string GenerateSessionId()
{
	boost::uuids::random_generator randGen;
	boost::uuids::uuid uuid(randGen());

	static_assert(cppcodec::detail::hex<cppcodec::detail::hex_lower>::encoded_size(sizeof(uuid.data)) + 1 == LocalConnectStruct::UUID_STR_LEN,
		"The encoded size must be eqaul to the string length!");

	return cppcodec::hex_lower::encode(uuid.data, sizeof(uuid.data));
}

LocalAcceptor::LocalAcceptor(const std::string & serverName) :
	m_sharedObj(std::make_shared<SharedObject<LocalConnectStruct> >(serverName, true))
{
}

LocalAcceptor::LocalAcceptor(LocalAcceptor && other) :
	m_sharedObj(std::move(other.m_sharedObj))
{
}

LocalAcceptor::~LocalAcceptor()
{
}

LocalAcceptor & LocalAcceptor::operator=(LocalAcceptor && other)
{
	if (this != &other)
	{
		m_sharedObj = std::move(other.m_sharedObj);
	}
	return *this;
}

bool LocalAcceptor::IsTerminate() const
{
	std::shared_ptr<const SharedObject<LocalConnectStruct> > obj = std::atomic_load(&m_sharedObj);
	return obj->GetObject().IsClosed();
}

void LocalAcceptor::Terminate()
{
	std::shared_ptr<SharedObject<LocalConnectStruct> > obj = std::atomic_load(&m_sharedObj);
	obj->GetObject().SetClose();

	obj->GetObject().m_idReadySignal.notify_all();
	obj->GetObject().m_connectSignal.notify_all();
}

std::pair<std::shared_ptr<SharedObject<LocalSessionStruct> >, std::shared_ptr<SharedObject<LocalSessionStruct> > > LocalAcceptor::Accept()
{
	std::shared_ptr<SharedObject<LocalConnectStruct> > obj = std::atomic_load(&m_sharedObj);

	scoped_lock<interprocess_mutex> lock(obj->GetObject().m_writeLock);

	obj->GetObject().m_connectSignal.wait(lock);

	std::string uuid = GenerateSessionId();

	std::shared_ptr<SharedObject<LocalSessionStruct> > sharedObj_s2c(std::make_shared<SharedObject<LocalSessionStruct> >((uuid + "S2C"), true));
	std::shared_ptr<SharedObject<LocalSessionStruct> > sharedObj_c2s(std::make_shared<SharedObject<LocalSessionStruct> >((uuid + "C2S"), true));

	std::memcpy(obj->GetObject().m_msg, uuid.c_str(), sizeof(obj->GetObject().m_msg));
	obj->GetObject().m_idReadySignal.notify_one();

	return std::make_pair(sharedObj_c2s, sharedObj_s2c);
}

LocalServer::LocalServer(const std::string & serverName) :
	m_acceptor(serverName)
{
}

LocalServer::LocalServer(LocalServer && other) :
	m_acceptor(std::move(other.m_acceptor))
{
}

LocalServer::~LocalServer()
{
}

LocalServer & LocalServer::operator=(LocalServer && other)
{
	if (this != &other)
	{
		m_acceptor = std::move(other.m_acceptor);
	}
	return *this;
}

std::unique_ptr<Connection> LocalServer::AcceptConnection()
{
	return std::make_unique<LocalConnection>(m_acceptor);
}
