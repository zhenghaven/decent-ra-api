#include "LocalConnection.h"

#include <cstring>
#include <atomic>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <json/json.h>

#include "../../common/JsonTools.h"

//#include "../Common.h"
#include "../Messages.h"

#include "LocalServer.h"
#include "LocalConnectionStructs.h"
#include "NetworkException.h"

using namespace boost::interprocess;

#define CONNECTION_CLOSED_CHECK(X) if (X)\
								   {\
								   throw ConnectionClosedException();\
								   }

Connection* LocalConnection::Connect(const std::string & serverName)
{
	std::shared_ptr<SharedObject<LocalConnectStruct> > sharedAcc(std::make_shared<SharedObject<LocalConnectStruct> >(serverName, false));

	scoped_lock<interprocess_mutex> connectlock(sharedAcc->GetObject().m_connectLock);
	scoped_lock<interprocess_mutex> writelock(sharedAcc->GetObject().m_writeLock);

	sharedAcc->GetObject().m_connectSignal.notify_one();

	CONNECTION_CLOSED_CHECK(sharedAcc->GetObject().IsClosed());
	sharedAcc->GetObject().m_idReadySignal.wait(writelock);
	CONNECTION_CLOSED_CHECK(sharedAcc->GetObject().IsClosed());

	std::string sessionId(sharedAcc->GetObject().m_msg);

	return new LocalConnection(sessionId);
}

LocalConnection::LocalConnection(const std::string & sessionId) :
	m_inSharedObj(std::make_shared<SharedObject<LocalSessionStruct> >((sessionId + "S2C"), false)),
	m_outSharedObj(std::make_shared<SharedObject<LocalSessionStruct> >((sessionId + "C2S"), false))
{
}

LocalConnection::LocalConnection(LocalAcceptor & acceptor) :
	LocalConnection(acceptor.Accept())
{
}

LocalConnection::LocalConnection(const std::pair<std::shared_ptr<SharedObject<LocalSessionStruct> >, std::shared_ptr<SharedObject<LocalSessionStruct> > >& sharedObjs) noexcept :
	m_inSharedObj(std::move(sharedObjs.first)),
	m_outSharedObj(std::move(sharedObjs.second))
{
}

LocalConnection::LocalConnection(LocalConnection && other) noexcept:
	m_inSharedObj(std::move(other.m_inSharedObj)),
	m_outSharedObj(std::move(other.m_outSharedObj))
{
}

LocalConnection::~LocalConnection()
{
	Terminate();
}

LocalConnection & LocalConnection::operator=(LocalConnection && other)
{
	if (this != &other)
	{
		m_inSharedObj = std::move(other.m_inSharedObj);
		m_outSharedObj = std::move(other.m_outSharedObj);
	}
	return *this;
}

size_t LocalConnection::Send(const Messages & msg)
{
	return Send(msg.ToJsonString());
}

size_t LocalConnection::Send(const std::string & msg)
{
	size_t sentSize = Send(msg.data(), msg.size());
	//LOGI("Sent Msg (len=%llu): \n%s\n", static_cast<unsigned long long>(sentSize), msg.c_str());
	return sentSize;
}

size_t LocalConnection::Send(const Json::Value & msg)
{
	return Send(msg.toStyledString());
}

size_t LocalConnection::Send(const std::vector<uint8_t>& msg)
{
	size_t sentSize = Send(msg.data(), msg.size());
	//LOGI("Sent Binary with size %llu\n", static_cast<unsigned long long>(sentSize));
	return sentSize;
}

size_t LocalConnection::Send(const void * const dataPtr, const size_t size)
{
	uint64_t sentSize = 0;
	const uint8_t* const bytePtr = static_cast<const uint8_t*>(dataPtr);

	std::shared_ptr<SharedObject<LocalSessionStruct> > outSharedObj = std::atomic_load(&m_outSharedObj);
	LocalSessionStruct& m_dataRef = outSharedObj->GetObject();

	while (sentSize < size)
	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.IsClosed());
			m_dataRef.m_emptySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(m_dataRef.IsClosed());

		m_dataRef.m_totalSize = static_cast<uint64_t>(size) - sentSize;
		m_dataRef.m_sentSize = m_dataRef.m_totalSize < LocalSessionStruct::MSG_SIZE ? static_cast<uint32_t>(m_dataRef.m_totalSize) : LocalSessionStruct::MSG_SIZE;

		std::memcpy(m_dataRef.m_msg, bytePtr + sentSize, m_dataRef.m_sentSize);
		sentSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = true;

		m_dataRef.m_readySignal.notify_one();
	}

	return sentSize;
}

size_t LocalConnection::Receive(std::string & msg)
{
	uint64_t recvSize = 0;
	uint64_t totalSize = 0;

	std::shared_ptr<SharedObject<LocalSessionStruct> > inSharedObj = std::atomic_load(&m_inSharedObj);
	LocalSessionStruct& m_dataRef = inSharedObj->GetObject();

	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (!m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.IsClosed());
			m_dataRef.m_readySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(!m_dataRef.m_isMsgReady);
		totalSize = m_dataRef.m_totalSize;
		msg.resize(totalSize);

		std::memcpy(&msg[recvSize], m_dataRef.m_msg, m_dataRef.m_sentSize);
		recvSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = false;

		m_dataRef.m_emptySignal.notify_one();
	}

	while (recvSize < totalSize)
	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (!m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.IsClosed());
			m_dataRef.m_readySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(!m_dataRef.m_isMsgReady);

		std::memcpy(&msg[recvSize], m_dataRef.m_msg, m_dataRef.m_sentSize);
		recvSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = false;

		m_dataRef.m_emptySignal.notify_one();
	}

	//LOGI("Recv Msg (len=%llu): \n%s\n", static_cast<unsigned long long>(recvSize), msg.c_str());
	return recvSize;
}

size_t LocalConnection::Receive(Json::Value & msg)
{
	std::string buffer;
	size_t res = Receive(buffer);
	bool isValid = ParseStr2Json(msg, buffer);
	return isValid ? res : 0;
}

size_t LocalConnection::Receive(std::vector<uint8_t>& msg)
{
	uint64_t recvSize = 0;
	uint64_t totalSize = 0;

	std::shared_ptr<SharedObject<LocalSessionStruct> > inSharedObj = std::atomic_load(&m_inSharedObj);
	LocalSessionStruct& m_dataRef = inSharedObj->GetObject();

	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (!m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.IsClosed());
			m_dataRef.m_readySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(!m_dataRef.m_isMsgReady);
		totalSize = m_dataRef.m_totalSize;
		msg.resize(totalSize);

		std::memcpy(&msg[recvSize], m_dataRef.m_msg, m_dataRef.m_sentSize);
		recvSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = false;

		m_dataRef.m_emptySignal.notify_one();
	}

	while (recvSize < totalSize)
	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (!m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.IsClosed());
			m_dataRef.m_readySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(!m_dataRef.m_isMsgReady);

		std::memcpy(&msg[recvSize], m_dataRef.m_msg, m_dataRef.m_sentSize);
		recvSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = false;

		m_dataRef.m_emptySignal.notify_one();
	}

	//LOGI("Recv Binary with size %llu\n", recvSize);
	return recvSize;
}

bool LocalConnection::IsTerminate() const noexcept
{
	std::shared_ptr<const SharedObject<LocalSessionStruct> > inSharedObj = std::atomic_load(&m_inSharedObj); //noexcept based on cppreference.
	std::shared_ptr<const SharedObject<LocalSessionStruct> > outSharedObj = std::atomic_load(&m_outSharedObj); //noexcept
	
	return (!inSharedObj || inSharedObj->GetObject().IsClosed()) && (!outSharedObj || inSharedObj->GetObject().IsClosed()); //noexcept
}

void LocalConnection::Terminate() noexcept
{
	if (IsTerminate())
	{
		return;
	}

	std::shared_ptr<SharedObject<LocalSessionStruct> > inSharedObj = std::atomic_load(&m_inSharedObj);
	std::shared_ptr<SharedObject<LocalSessionStruct> > outSharedObj = std::atomic_load(&m_outSharedObj);

	if (inSharedObj)
	{
		inSharedObj->GetObject().SetClose();
		inSharedObj->GetObject().m_emptySignal.notify_all();
		inSharedObj->GetObject().m_readySignal.notify_all();
	}

	if (outSharedObj)
	{
		outSharedObj->GetObject().SetClose();
		outSharedObj->GetObject().m_emptySignal.notify_all();
		outSharedObj->GetObject().m_readySignal.notify_all();
	}
}
