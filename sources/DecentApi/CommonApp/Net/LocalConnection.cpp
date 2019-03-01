#include "LocalConnection.h"

#include <cstring>
#include <atomic>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include "LocalServer.h"
#include "LocalConnectionStructs.h"
#include "../../Common/Net/NetworkException.h"

using namespace boost::interprocess;
using namespace Decent::Net;

#define CONNECTION_CLOSED_CHECK(X) if (X)\
								   {\
								   throw ConnectionClosedException();\
								   }


template<typename PrForWait, typename PrForThrow>
static void TimedWait(interprocess_condition& cond, scoped_lock<interprocess_mutex>& lock, PrForWait prWait, PrForThrow prThrow)
{
	boost::posix_time::ptime timeout;
	do
	{
		timeout = microsec_clock::universal_time() + boost::posix_time::milliseconds(2000);
	} while (!cond.timed_wait(lock, timeout, prWait));
	
	CONNECTION_CLOSED_CHECK(prThrow());
}

LocalConnection LocalConnection::Connect(const std::string & serverName)
{
	std::unique_ptr<SharedObject<LocalConnectStruct> > sharedAcc(new SharedObject<LocalConnectStruct>(serverName, false));

	LocalConnectStruct& objRef = sharedAcc->GetObject();

	scoped_lock<interprocess_mutex> connectlock(objRef.m_connectLock);
	scoped_lock<interprocess_mutex> writelock(objRef.m_writeLock);

	objRef.m_connectSignal.notify_one();

	TimedWait(objRef.m_idReadySignal, writelock, [&objRef]() -> bool {
		return objRef.IsClosed() || objRef.m_isMsgReady;
	}, [&objRef]() -> bool {
		return objRef.IsClosed();
	});

	std::string sessionId(sharedAcc->GetObject().m_msg);
	objRef.m_isMsgReady = false;

	return sessionId;
}

LocalConnection::LocalConnection(const std::string & sessionId) :
	m_inSharedObj(new SharedObject<LocalSessionStruct>((sessionId + SESSION_NAME_S2C_POSTFIX), false)),
	m_outSharedObj(new SharedObject<LocalSessionStruct>((sessionId + SESSION_NAME_C2S_POSTFIX), false)),
	m_inMsgQ(new LocalMessageQueue(sessionId + QUEUE_NAME_S2C_POSTFIX, false)),
	m_outMsgQ(new LocalMessageQueue(sessionId + QUEUE_NAME_C2S_POSTFIX, false))
{
}

LocalConnection::LocalConnection(LocalAcceptor & acceptor) :
	LocalConnection(acceptor.Accept())
{
}

LocalConnection::LocalConnection(LocalAcceptedResult&& sharedObjs) noexcept :
	m_inSharedObj(std::move(sharedObjs.m_sharedObj_a)),
	m_outSharedObj(std::move(sharedObjs.m_sharedObj_b)),
	m_inMsgQ(std::move(sharedObjs.m_msgQ_a)),
	m_outMsgQ(std::move(sharedObjs.m_msgQ_b))
{
}

LocalConnection::LocalConnection(LocalConnection && other) noexcept:
	m_inSharedObj(std::move(other.m_inSharedObj)),
	m_outSharedObj(std::move(other.m_outSharedObj)),
	m_inMsgQ(std::move(other.m_inMsgQ)),
	m_outMsgQ(std::move(other.m_outMsgQ))
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

size_t LocalConnection::SendRaw(const void * const dataPtr, const size_t size)
{
	LocalSessionStruct& dataRef = m_outSharedObj->GetObject();
	size_t totalSentSize = 0;

	{
		scoped_lock<interprocess_mutex> writelock(dataRef.m_msgLock);
		CONNECTION_CLOSED_CHECK(dataRef.IsClosed());

		//size_t sizeToSent = LocalMessageQueue::MSG_SIZE - m_outMsgQ->GetQ().get_num_msg();
		//sizeToSent = size < sizeToSent ? size : sizeToSent;

		bool sentRes = true;

		while (totalSentSize < size && sentRes)
		{
			sentRes = m_outMsgQ->GetQ().try_send(reinterpret_cast<const uint8_t*>(dataPtr) + totalSentSize,
				LocalMessageQueue::CHUNK_SIZE, LocalMessageQueue::DEFAULT_PRIORITY);

			totalSentSize += LocalMessageQueue::CHUNK_SIZE;
		}
		totalSentSize -= sentRes ? 0 : LocalMessageQueue::CHUNK_SIZE;

		dataRef.m_isMsgReady = true;
	}

	dataRef.m_readySignal.notify_one();
	return totalSentSize;
}

size_t LocalConnection::ReceiveRaw(void * const bufPtr, const size_t size)
{
	LocalSessionStruct& dataRef = m_inSharedObj->GetObject();

	scoped_lock<interprocess_mutex> writelock(dataRef.m_msgLock); 
	if (!dataRef.m_isMsgReady)
	{
		TimedWait(dataRef.m_readySignal, writelock, [&dataRef]() -> bool {
			return dataRef.IsClosed() || dataRef.m_isMsgReady;
		}, [&dataRef]() -> bool {
			return dataRef.IsClosed();
		});
	}

	unsigned int priority = 0;
	size_t recvSize = 0;
	size_t totalRecvSize = 0;
	bool recvRes = true;

	while (totalRecvSize < size && recvRes)
	{
		recvRes = m_inMsgQ->GetQ().try_receive(reinterpret_cast<uint8_t*>(bufPtr) + totalRecvSize, LocalMessageQueue::CHUNK_SIZE,
			recvSize, priority);

		totalRecvSize += recvSize;
	}
	totalRecvSize -= recvRes ? 0 : recvSize;

	dataRef.m_isMsgReady = false;

	return totalRecvSize;
}

bool LocalConnection::IsTerminate() const noexcept
{
	return (!m_inSharedObj || m_inSharedObj->GetObject().IsClosed()) && (!m_outSharedObj || m_outSharedObj->GetObject().IsClosed()); //noexcept
}

void LocalConnection::Terminate() noexcept
{
	if (IsTerminate())
	{
		return;
	}

	if (m_inSharedObj)
	{
		m_inSharedObj->GetObject().SetClose();
		m_inSharedObj->GetObject().m_readySignal.notify_all();
	}

	if (m_outSharedObj)
	{
		m_outSharedObj->GetObject().SetClose();
		m_outSharedObj->GetObject().m_readySignal.notify_all();
	}
}
