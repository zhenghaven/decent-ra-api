#include "TlsConnectionPool.h"

#include "TlsCommLayer.h"

using namespace Decent::Net;

TlsConnectionPool::TlsConnectionPool(size_t maxInCnt, size_t maxOutCnt) :
	m_maxInCnt(maxInCnt),
	m_maxOutCnt(maxOutCnt),
	m_inCntCount()
{
}

TlsConnectionPool::~TlsConnectionPool()
{
}

bool Decent::Net::TlsConnectionPool::HoldInComingConnection(TlsCommLayer & tls)
{
	uint64_t currentCount = m_inCntCount++;
	if (currentCount >= m_maxInCnt)
	{
		//There is no more space
		m_inCntCount--;
		return false;
	}

	//Decent keep-alive protocol
	try
	{
		char wakeMsg = 'W';
		tls.SendStruct('?');
		tls.ReceiveStruct(wakeMsg); //Waitting wake-up message.

		// For simplicity, we assume peer correctly follows the protocol, 
		// thus, we don't check the message content, for now.
	}
	catch (const std::exception&)
	{
		//Probably peer terminates the connection.
		m_inCntCount--;
		return false;
	}

	//Successfully waken-up.
	m_inCntCount--;
	return true;
}
