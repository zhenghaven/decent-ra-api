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
	m_sharedObj(std::make_shared<SharedObject<LocalConnectStruct> >(serverName, true)),
	m_isTerminated(0)
{
}

LocalAcceptor::LocalAcceptor(LocalAcceptor && other) :
	m_sharedObj(std::move(other.m_sharedObj)),
	m_isTerminated(static_cast<uint8_t>(other.m_isTerminated))
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
		m_isTerminated = static_cast<uint8_t>(other.m_isTerminated);
	}
	return *this;
}

bool LocalAcceptor::IsTerminate() const noexcept
{
	return m_isTerminated.load();
}

void LocalAcceptor::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}

	std::shared_ptr<SharedObject<LocalConnectStruct> > obj = std::atomic_load(&m_sharedObj);
	if (obj)
	{
		obj->GetObject().SetClose();

		obj->GetObject().m_idReadySignal.notify_all();
		obj->GetObject().m_connectSignal.notify_all();
	}
}

std::pair<
	std::pair<SharedObject<LocalSessionStruct>*, LocalMessageQueue*>,
	std::pair<SharedObject<LocalSessionStruct>*, LocalMessageQueue*> > LocalAcceptor::Accept()
{
	std::pair<
		std::pair<SharedObject<LocalSessionStruct>*, LocalMessageQueue*>,
		std::pair<SharedObject<LocalSessionStruct>*, LocalMessageQueue*> > emptyRet(std::make_pair(nullptr, nullptr), std::make_pair(nullptr, nullptr));
	if (m_isTerminated)
	{
		return emptyRet;
	}

	std::shared_ptr<SharedObject<LocalConnectStruct> > obj = std::atomic_load(&m_sharedObj);

	std::unique_ptr<SharedObject<LocalSessionStruct> > sharedObj_s2c;
	std::unique_ptr<SharedObject<LocalSessionStruct> > sharedObj_c2s;
	std::unique_ptr<LocalMessageQueue> msgQ_s2c;
	std::unique_ptr<LocalMessageQueue> msgQ_c2s;

	{
		scoped_lock<interprocess_mutex> lock(obj->GetObject().m_writeLock);
		obj->GetObject().m_connectSignal.wait(lock);

		std::string uuid = GenerateSessionId();

		sharedObj_s2c.reset(new SharedObject<LocalSessionStruct>((uuid + SESSION_NAME_S2C_POSTFIX), true));
		sharedObj_c2s.reset(new SharedObject<LocalSessionStruct>((uuid + SESSION_NAME_C2S_POSTFIX), true));
		msgQ_s2c.reset(new LocalMessageQueue((uuid + QUEUE_NAME_S2C_POSTFIX), true));
		msgQ_c2s.reset(new LocalMessageQueue((uuid + QUEUE_NAME_C2S_POSTFIX), true));

		std::memcpy(obj->GetObject().m_msg, uuid.c_str(), sizeof(obj->GetObject().m_msg));
		obj->GetObject().m_isMsgReady = true;
	}

	obj->GetObject().m_idReadySignal.notify_one();

	return std::make_pair(
		std::make_pair(sharedObj_c2s.release(), msgQ_c2s.release()),
		std::make_pair(sharedObj_s2c.release(), msgQ_s2c.release()));
}

LocalServer::LocalServer(const std::string & serverName) :
	m_acceptor(serverName),
	m_isTerminated(0)
{
}

LocalServer::LocalServer(LocalServer && other) :
	m_acceptor(std::move(other.m_acceptor)),
	m_isTerminated(static_cast<uint8_t>(other.m_isTerminated))
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
		m_isTerminated = static_cast<uint8_t>(other.m_isTerminated);
	}
	return *this;
}

std::unique_ptr<Connection> LocalServer::AcceptConnection() noexcept
{
	if (m_isTerminated)
	{
		return nullptr;
	}
	try
	{
		std::unique_ptr<Connection> ptr = std::make_unique<LocalConnection>(m_acceptor);
		if (m_isTerminated)
		{
			return nullptr;
		}
		return std::move(ptr);
	}
	catch (const std::exception&)
	{
		return nullptr;
	}
}

bool LocalServer::IsTerminated() noexcept
{
	return m_isTerminated.load();
}

void LocalServer::Terminate() noexcept
{
	if (m_isTerminated)
	{
		return;
	}
	m_isTerminated = 1;
	m_acceptor.Terminate();
}
