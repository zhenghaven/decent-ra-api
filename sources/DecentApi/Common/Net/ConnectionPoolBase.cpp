#include "ConnectionPoolBase.h"

#include "ConnectionBase.h"

using namespace Decent::Net;

void ConnectionPoolBase::ClientAckKeepAlive(ConnectionBase & cnt)
{
	char serverQuery;
	cnt.RecvRawAll(&serverQuery, sizeof(serverQuery));
}

void ConnectionPoolBase::ClientWakePeer(ConnectionBase & cnt)
{
	cnt.SendRawAll(&sk_clientWakeMsg, sizeof(sk_clientWakeMsg));
}

void ConnectionPoolBase::ServerAsk(ConnectionBase & cnt)
{
	cnt.SendRawAll(&sk_serverAskMsg, sizeof(sk_serverAskMsg));
}

void ConnectionPoolBase::ServerWaitWakeUpMsg(ConnectionBase & cnt)
{
	char wakeMsg;
	cnt.RecvRawAll(&wakeMsg, sizeof(wakeMsg)); //Waitting wake-up message.
}

ConnectionPoolBase::ConnectionPoolBase(size_t maxInCnt) :
	m_maxInCnt(maxInCnt),
	m_inCntCount()
{
}

ConnectionPoolBase::~ConnectionPoolBase()
{
	std::unique_lock<std::mutex> serverQueueLock(m_serverQueueMutex);
	for (auto it = m_serverQueue.begin(); it != m_serverQueue.end(); ++it)
	{
		(*it)->Terminate();
	}
}

bool ConnectionPoolBase::HoldInComingConnection(ConnectionBase& cnt)
{
	if (m_maxInCnt == 0)
	{
		return false;
	}

	AddOneAndCheckCapacity();

	//Decent keep-alive protocol
	try
	{
		ConnectionPoolBase::ServerAsk(cnt);
		AddConnection2Queue(cnt);
		ConnectionPoolBase::ServerWaitWakeUpMsg(cnt);

		// For simplicity, we assume peer correctly follows the protocol,
		// thus, we don't check the message content, for now.

		RemoveFromQueue(cnt);
	}
	catch (const std::exception&)
	{
		//Probably peer terminates the connection.
		RemoveFromQueue(cnt);
		return false;
	}

	//Successfully waken-up.
	return true;
}

void ConnectionPoolBase::TerminateOldestIdleConnection()
{
	std::unique_lock<std::mutex> serverQueueLock(m_serverQueueMutex);
	if (m_serverQueue.size() > 0)
	{
		m_serverQueue.front()->Terminate();
		m_serverQueue.pop_front();
		serverQueueLock.unlock();
		m_inCntCount--;
	}
}

void ConnectionPoolBase::AddOneAndCheckCapacity()
{
	uint64_t currentCount = m_inCntCount++;
	//LOGI("InComing Cnt Count: %llu.", currentCount);
	if (currentCount >= m_maxInCnt)
	{
		//There is no more space
		TerminateOldestIdleConnection();
	}
}

void ConnectionPoolBase::AddConnection2Queue(ConnectionBase & cnt)
{
	std::unique_lock<std::mutex> serverQueueLock(m_serverQueueMutex);
	m_serverQueue.push_back(&cnt);
}

void ConnectionPoolBase::RemoveFromQueue(ConnectionBase & cnt)
{
	std::unique_lock<std::mutex> serverQueueLock(m_serverQueueMutex);
	for (auto it = m_serverQueue.begin(); it != m_serverQueue.end(); ++it)
	{
		if (*it == &cnt)
		{
			m_serverQueue.erase(it);
			m_inCntCount--;
			return;
		}
	}
}
