#include "SecureConnectionPoolBase.h"

#include "SecureCommLayer.h"
#include "ConnectionBase.h"

using namespace Decent::Net;

CntPair::CntPair(std::unique_ptr<ConnectionBase>&& cnt, std::unique_ptr<SecureCommLayer>&& comm) :
	m_cnt(std::forward<std::unique_ptr<ConnectionBase> >(cnt)),
	m_comm(std::forward<std::unique_ptr<SecureCommLayer> >(comm))
{
}

CntPair::CntPair(std::unique_ptr<ConnectionBase>& cnt, std::unique_ptr<SecureCommLayer>& comm) :
	m_cnt(std::move(cnt)),
	m_comm(std::move(comm))
{
}

CntPair::CntPair(CntPair && rhs) :
	m_cnt(std::forward<std::unique_ptr<ConnectionBase> >(rhs.m_cnt)),
	m_comm(std::forward<std::unique_ptr<SecureCommLayer> >(rhs.m_comm))
{
}

CntPair::~CntPair()
{
}

SecureCommLayer & CntPair::GetCommLayer()
{
	return *m_comm;
}

ConnectionBase & CntPair::GetConnection()
{
	return *m_cnt;
}

CntPair & CntPair::operator=(CntPair && rhs)
{
	if (this != &rhs)
	{
		m_cnt = std::forward<std::unique_ptr<ConnectionBase> >(rhs.m_cnt);
		m_comm = std::forward<std::unique_ptr<SecureCommLayer> >(rhs.m_comm);
	}

	return *this;
}

CntPair & CntPair::Swap(CntPair & other)
{
	m_cnt.swap(other.m_cnt);
	m_comm.swap(other.m_comm);
	return *this;
}

void SecureConnectionPoolBase::ClientAckKeepAlive(CntPair & cntPair)
{
	char serverQuery;
	cntPair.GetCommLayer().ReceiveStruct(serverQuery);
}

SecureConnectionPoolBase::SecureConnectionPoolBase(size_t maxInCnt) :
	m_maxInCnt(maxInCnt),
	m_inCntCount()
{
}

SecureConnectionPoolBase::~SecureConnectionPoolBase()
{
}

bool Decent::Net::SecureConnectionPoolBase::HoldInComingConnection(SecureCommLayer& secComm)
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
		secComm.SendStruct('?');
		secComm.ReceiveStruct(wakeMsg); //Waitting wake-up message.

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
