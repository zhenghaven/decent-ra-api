#include "LocalConnection.h"

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include "LocalServer.h"
#include "LocalConnectionStructs.h"
#include "NetworkException.h"

using namespace boost::interprocess;

Connection* LocalConnection::Connect(const std::string & serverName)
{
	try
	{
		shared_memory_object shm(open_only, serverName.c_str(), read_write);

		mapped_region region(shm, read_write);

		LocalConnectStruct * connectStrc = static_cast<LocalConnectStruct*>(region.get_address());

		scoped_lock<interprocess_mutex> connectlock(connectStrc->m_connectLock);
		scoped_lock<interprocess_mutex> writelock(connectStrc->m_writeLock);
	
		if (connectStrc->m_isClosed)
		{
			throw ConnectionClosedException();
		}

		connectStrc->m_connectSignal.notify_one();

		connectStrc->m_idReadySignal.wait(writelock);

		if (connectStrc->m_isClosed)
		{
			throw ConnectionClosedException();
		}

		std::string sessionId(connectStrc->m_msg);

		return new LocalConnection(sessionId);
	} 
	catch (ConnectionClosedException& e)
	{
		shared_memory_object::remove(serverName.c_str());
		throw e;
	}
}

static inline shared_memory_object* OpenConnection(const std::string & sessionId)
{
	return new shared_memory_object(open_only, sessionId.c_str(), read_write);
}

LocalConnection::LocalConnection(const std::string & sessionId):
	LocalConnection(OpenConnection(sessionId))
{
}

LocalConnection::LocalConnection(LocalAcceptor & acceptor) :
	LocalConnection(acceptor.Accept())
{
}

LocalConnection::LocalConnection(boost::interprocess::shared_memory_object* sharedObj) :
	LocalConnection(sharedObj, new mapped_region(*sharedObj, read_write))
{
}

LocalConnection::LocalConnection(boost::interprocess::shared_memory_object* sharedObj, boost::interprocess::mapped_region* mapReg) :
	//m_sessionName(sharedObj->get_name()),
	m_sharedObj(sharedObj),
	m_mapReg(mapReg),
	m_dataPtr(static_cast<LocalSessionStruct*>(mapReg->get_address()))
{

}

LocalConnection::~LocalConnection()
{
}

size_t LocalConnection::Send(const Messages & msg)
{
	return size_t();
}

size_t LocalConnection::Send(const std::string & msg)
{
	return size_t();
}

size_t LocalConnection::Send(const Json::Value & msg)
{
	return size_t();
}

size_t LocalConnection::Send(const std::vector<uint8_t>& msg)
{
	return size_t();
}

size_t LocalConnection::Send(const void * const dataPtr, const size_t size)
{
	return size_t();
}

size_t LocalConnection::Receive(std::string & msg)
{
	return size_t();
}

size_t LocalConnection::Receive(Json::Value & msg)
{
	return size_t();
}

size_t LocalConnection::Receive(std::vector<uint8_t>& msg)
{
	return size_t();
}
