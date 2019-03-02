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
#include "../../Common/Net/NetworkException.h"

using namespace boost::interprocess;
using namespace Decent::Net;

#define ACCEPTOR_CLOSED_CHECK if (m_connectStruct->IsClosed())\
								 {\
								 throw ConnectionClosedException();\
								 }

namespace
{
	static std::string GenerateSessionId()
	{
		boost::uuids::random_generator randGen;
		boost::uuids::uuid uuid(randGen());

		static_assert(cppcodec::detail::hex<cppcodec::detail::hex_lower>::encoded_size(sizeof(uuid.data)) + 1 == LocalConnectStruct::UUID_STR_LEN,
			"The encoded size must be eqaul to the string length!");

		return cppcodec::hex_lower::encode(uuid.data, sizeof(uuid.data));
	}
}

LocalAcceptedResult::LocalAcceptedResult() noexcept
{
}

LocalAcceptedResult::~LocalAcceptedResult()
{
}

LocalAcceptedResult::LocalAcceptedResult(std::unique_ptr<SharedObject<LocalSessionStruct>>& sharedObj_a, 
	std::unique_ptr<LocalMessageQueue>& msgQ_a, 
	std::unique_ptr<SharedObject<LocalSessionStruct>>& sharedObj_b, 
	std::unique_ptr<LocalMessageQueue>& msgQ_b) noexcept:
m_sharedObj_a(std::move(sharedObj_a)),
m_msgQ_a(std::move(msgQ_a)),
m_sharedObj_b(std::move(sharedObj_b)),
m_msgQ_b(std::move(msgQ_b))
{}

LocalAcceptedResult::LocalAcceptedResult(LocalAcceptedResult && rhs) noexcept :
m_sharedObj_a(std::move(rhs.m_sharedObj_a)),
m_msgQ_a(std::move(rhs.m_msgQ_a)),
m_sharedObj_b(std::move(rhs.m_sharedObj_b)),
m_msgQ_b(std::move(rhs.m_msgQ_b))
{}

LocalAcceptor::LocalAcceptor(const std::string & serverName) :
	m_sharedObj(std::make_shared<SharedObject<LocalConnectStruct> >(serverName, true)),
	m_isTerminated(0)
{
}

LocalAcceptor::LocalAcceptor(LocalAcceptor && other) noexcept :
	m_sharedObj(std::move(other.m_sharedObj)),
	m_isTerminated(static_cast<uint8_t>(other.m_isTerminated))
{
}

LocalAcceptor::~LocalAcceptor()
{
}

LocalAcceptor & LocalAcceptor::operator=(LocalAcceptor && other) noexcept
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

LocalAcceptedResult LocalAcceptor::Accept()
{
	if (m_isTerminated)
	{
		return LocalAcceptedResult();
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

		sharedObj_s2c = std::make_unique<SharedObject<LocalSessionStruct> >((uuid + SESSION_NAME_S2C_POSTFIX), true);
		sharedObj_c2s = std::make_unique<SharedObject<LocalSessionStruct> >((uuid + SESSION_NAME_C2S_POSTFIX), true);
		msgQ_s2c = std::make_unique<LocalMessageQueue>((uuid + QUEUE_NAME_S2C_POSTFIX), true);
		msgQ_c2s = std::make_unique<LocalMessageQueue>((uuid + QUEUE_NAME_C2S_POSTFIX), true);

		std::memcpy(obj->GetObject().m_msg, uuid.c_str(), sizeof(obj->GetObject().m_msg));
		obj->GetObject().m_isMsgReady = true;
	}

	obj->GetObject().m_idReadySignal.notify_one();

	return LocalAcceptedResult(sharedObj_c2s, msgQ_c2s, sharedObj_s2c, msgQ_s2c);
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

std::unique_ptr<Connection> LocalServer::AcceptConnection()
{
	if (m_isTerminated)
	{
		return nullptr;
	}

	return std::make_unique<LocalConnection>(m_acceptor);
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
