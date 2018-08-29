#include "LocalConnection.h"

#include <cstring>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <json/json.h>

#include "../../common/JsonTools.h"

#include "../Common.h"
#include "../Messages.h"

#include "LocalServer.h"
#include "LocalConnectionStructs.h"
#include "NetworkException.h"

using namespace boost::interprocess;

#define ACCEPTOR_CLOSED_CHECK if (acceptorPtr.m_isClosed)\
								 {\
								 throw ConnectionClosedException();\
								 }

#define CONNECTION_CLOSED_CHECK(X) if (X)\
								   {\
								   throw ConnectionClosedException();\
								   }

Connection* LocalConnection::Connect(const std::string & serverName)
{
	try
	{
		shared_memory_object shm(open_only, serverName.c_str(), read_write);

		mapped_region region(shm, read_write);

		LocalConnectStruct& acceptorPtr = *static_cast<LocalConnectStruct*>(region.get_address());

		scoped_lock<interprocess_mutex> connectlock(acceptorPtr.m_connectLock);
		scoped_lock<interprocess_mutex> writelock(acceptorPtr.m_writeLock);

		acceptorPtr.m_connectSignal.notify_one();

		ACCEPTOR_CLOSED_CHECK;
		acceptorPtr.m_idReadySignal.wait(writelock);
		ACCEPTOR_CLOSED_CHECK;

		if (acceptorPtr.m_isClosed)
		{
			throw ConnectionClosedException();
		}

		std::string sessionId(acceptorPtr.m_msg);

		return new LocalConnection(sessionId);
	} 
	catch (ConnectionClosedException& e)
	{
		shared_memory_object::remove(serverName.c_str());
		throw e;
	}
}

static inline std::pair<shared_memory_object*, shared_memory_object*> OpenConnection(const std::string & sessionId)
{
	shared_memory_object* sharedObjPtr_s2c = new shared_memory_object(open_only, (sessionId + "S2C").c_str(), read_write);
	shared_memory_object* sharedObjPtr_c2s = new shared_memory_object(open_only, (sessionId + "C2S").c_str(), read_write);
	return std::make_pair(sharedObjPtr_s2c, sharedObjPtr_c2s);
}

LocalConnection::LocalConnection(const std::string & sessionId):
	LocalConnection(OpenConnection(sessionId))
{
}

LocalConnection::LocalConnection(LocalAcceptor & acceptor) :
	LocalConnection(acceptor.Accept())
{
}

LocalConnection::LocalConnection(std::pair<boost::interprocess::shared_memory_object*, boost::interprocess::shared_memory_object*> sharedObjs) :
	LocalConnection(sharedObjs.first, new mapped_region(*(sharedObjs.first), read_write), sharedObjs.second, new mapped_region(*(sharedObjs.second), read_write))
{
}

LocalConnection::LocalConnection(boost::interprocess::shared_memory_object* inSharedObj, boost::interprocess::mapped_region* inMapReg, boost::interprocess::shared_memory_object* outSharedObj, boost::interprocess::mapped_region* outMapReg) :
	//m_sessionName(sharedObj->get_name()),
	m_inSharedObj(inSharedObj),
	m_inMapReg(inMapReg),
	m_inData(*static_cast<LocalSessionStruct*>(m_inMapReg->get_address())),
	m_outSharedObj(outSharedObj),
	m_outMapReg(outMapReg),
	m_outData(*static_cast<LocalSessionStruct*>(m_outMapReg->get_address()))
{

}

LocalConnection::~LocalConnection()
{
	std::string inSessionName = m_inSharedObj->get_name();
	std::string outSessionName = m_outSharedObj->get_name();

	Terminate();

	delete m_inSharedObj;
	delete m_outSharedObj;
	delete m_inMapReg;
	delete m_outMapReg;

	shared_memory_object::remove(inSessionName.c_str());
	shared_memory_object::remove(outSessionName.c_str());
}

size_t LocalConnection::Send(const Messages & msg)
{
	return Send(msg.ToJsonString());
}

size_t LocalConnection::Send(const std::string & msg)
{
	size_t sentSize = Send(msg.data(), msg.size());
	LOGI("Sent Msg (len=%llu): \n%s\n", static_cast<unsigned long long>(sentSize), msg.c_str());
	return sentSize;
}

size_t LocalConnection::Send(const Json::Value & msg)
{
	return Send(msg.toStyledString());
}

size_t LocalConnection::Send(const std::vector<uint8_t>& msg)
{
	size_t sentSize = Send(msg.data(), msg.size());
	LOGI("Sent Binary with size %llu\n", static_cast<unsigned long long>(sentSize));
	return sentSize;
}

size_t LocalConnection::Send(const void * const dataPtr, const size_t size)
{
	uint64_t sentSize = 0;
	const uint8_t* const bytePtr = static_cast<const uint8_t*>(dataPtr);
	LocalSessionStruct& m_dataRef = m_outData;

	while (sentSize < size)
	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.m_isClosed);
			m_dataRef.m_emptySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(m_dataRef.m_isClosed);

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
	LocalSessionStruct& m_dataRef = m_inData;

	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (!m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.m_isClosed);
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
			CONNECTION_CLOSED_CHECK(m_dataRef.m_isClosed);
			m_dataRef.m_readySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(!m_dataRef.m_isMsgReady);

		std::memcpy(&msg[recvSize], m_dataRef.m_msg, m_dataRef.m_sentSize);
		recvSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = false;

		m_dataRef.m_emptySignal.notify_one();
	}

	LOGI("Recv Msg (len=%llu): \n%s\n", static_cast<unsigned long long>(recvSize), msg.c_str());
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
	LocalSessionStruct& m_dataRef = m_inData;

	{
		scoped_lock<interprocess_mutex> writelock(m_dataRef.m_msgLock);
		if (!m_dataRef.m_isMsgReady)
		{
			CONNECTION_CLOSED_CHECK(m_dataRef.m_isClosed);
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
			CONNECTION_CLOSED_CHECK(m_dataRef.m_isClosed);
			m_dataRef.m_readySignal.wait(writelock);
		}
		CONNECTION_CLOSED_CHECK(!m_dataRef.m_isMsgReady);

		std::memcpy(&msg[recvSize], m_dataRef.m_msg, m_dataRef.m_sentSize);
		recvSize += m_dataRef.m_sentSize;
		m_dataRef.m_isMsgReady = false;

		m_dataRef.m_emptySignal.notify_one();
	}

	LOGI("Recv Binary with size %llu\n", recvSize);
	return recvSize;
}

bool LocalConnection::IsTerminate() const
{
	return m_inData.m_isClosed || m_outData.m_isClosed;
}

void LocalConnection::Terminate()
{
	m_inData.m_isClosed = m_outData.m_isClosed = true;

	m_inData.m_emptySignal.notify_all();
	m_inData.m_readySignal.notify_all();

	m_outData.m_emptySignal.notify_all();
	m_outData.m_readySignal.notify_all();
}
