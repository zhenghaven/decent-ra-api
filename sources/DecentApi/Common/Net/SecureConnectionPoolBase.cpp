#include "SecureConnectionPoolBase.h"

#include "SecureCommLayer.h"
#include "ConnectionBase.h"

using namespace Decent::Net;

CntPair::CntPair(std::unique_ptr<ConnectionBase> cnt, std::unique_ptr<SecureCommLayer> comm) :
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
	cntPair.GetCommLayer().RecvStruct(serverQuery);
}

void SecureConnectionPoolBase::ClientWakePeer(CntPair & cntPair)
{
	cntPair.GetCommLayer().SendStruct('W');
}

void SecureConnectionPoolBase::ServerAsk(SecureCommLayer & secComm)
{
	secComm.SendStruct('?');
}

void SecureConnectionPoolBase::ServerWaitWakeUpMsg(SecureCommLayer & secComm)
{
	char wakeMsg = 'W';
	secComm.RecvStruct(wakeMsg); //Waitting wake-up message.
}

bool SecureConnectionPoolBase::HoldInComingConnection(ConnectionBase& cnt, SecureCommLayer& secComm)
{
	if (GetMaxInConnection() == 0)
	{
		return false;
	}

	AddOneAndCheckCapacity();

	//Decent keep-alive protocol
	try
	{
		SecureConnectionPoolBase::ServerAsk(secComm);
		AddConnection2Queue(cnt);
		SecureConnectionPoolBase::ServerWaitWakeUpMsg(secComm);

		// For simplicity, we assume peer correctly follows the protocol, 
		// thus, we don't check the message content, for now.
		
		RemoveFromQueue(cnt);

		//Successfully waken-up.
		return true;
	}
	catch (const std::exception&)
	{
		//Probably peer terminates the connection.
		RemoveFromQueue(cnt);
		return false;
	}
}
