#include "LocalConnectionStructs.h"

#include <string>

#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>

#include "../../Common/Common.h"

#include "NetworkException.h"

using namespace Decent;
using namespace Decent::Net;
namespace bIp = boost::interprocess;

std::unique_ptr<bIp::shared_memory_object> Net::ConstructSharedObj(const std::string& objName, const size_t size, const bool isCreate)
{
	std::unique_ptr<bIp::shared_memory_object> res;
	try
	{
		if (isCreate)
		{
			bIp::shared_memory_object::remove(objName.c_str());
			res = std::make_unique<bIp::shared_memory_object>(bIp::create_only, objName.c_str(), bIp::read_write);
			res->truncate(size); //sizeof(T)
			LOGI("Created shared object, %s.", objName.c_str());
		}
		else
		{
			res = std::make_unique<bIp::shared_memory_object>(bIp::open_only, objName.c_str(), bIp::read_write);
		}
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at shared object construction.")

	return std::move(res);
}

std::unique_ptr<bIp::mapped_region> Net::ContructSharedMap(const bIp::shared_memory_object& sharedObj)
{
	try 
	{
		return std::make_unique<bIp::mapped_region>(sharedObj, bIp::read_write);
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at map region construction.")
}

void Net::DestructSharedMap(std::unique_ptr<bIp::mapped_region>& mapPtr) noexcept
{
	try { mapPtr.reset(); } catch(...){}
}

void Net::DestructSharedObj(std::unique_ptr<bIp::shared_memory_object>& objPtr, const bool isOwner) noexcept
{
	if (!objPtr)
	{
		return;
	}

	std::string objName;
	if (isOwner)
	{
		objName = objPtr->get_name();
	}

	try { objPtr.reset(); } catch (...) {}

	if (isOwner)
	{
		bool isClosed = bIp::shared_memory_object::remove(objName.c_str()); //shared_memory_object::remove does not throw exception.

		LOGI("Attempted to close shared object, %s - %s!", objName.c_str(), isClosed ? "Successful!" : "Failed!");
	}
}

std::unique_ptr<bIp::message_queue> Net::ConstructMsgQueue(const std::string & name, const bool isOwner)
{
	try
	{
		if (isOwner)
		{
			bIp::message_queue::remove(name.c_str());
			LOGI("Creating msg queue, %s...", name.c_str());
			return std::make_unique<bIp::message_queue>(bIp::create_only, name.c_str(),
				LocalMessageQueue::MSG_SIZE, sizeof(uint8_t));
		}
		else
		{
			return std::make_unique<bIp::message_queue>(bIp::open_only, name.c_str());
		}
	}
	RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION("Unknown exception caught at message queue construction.")
}

void Net::DestructMsgQueue(std::unique_ptr<bIp::message_queue>& queuePtr, const std::string& name, const bool isOwner) noexcept
{
	queuePtr.reset();

	if (isOwner)
	{
		bool isClosed = bIp::message_queue::remove(name.c_str()); //message_queue::remove does not throw exception.
		
		LOGI("Attempted to close msg queue, %s - %s!", name.c_str(), isClosed ? "Successful!" : "Failed!");
	}
}

constexpr size_t LocalMessageQueue::MSG_SIZE;

LocalMessageQueue::LocalMessageQueue(const std::string & name, const bool isOwner) :
	m_msgQ(ConstructMsgQueue(name, isOwner)),
	m_name(name),
	m_isOwner(isOwner)
{}

LocalMessageQueue::LocalMessageQueue(LocalMessageQueue && other) noexcept :
	m_msgQ(std::move(other.m_msgQ)),
	m_name(std::move(other.m_name)),
	m_isOwner(other.m_isOwner)
{
	m_isOwner = false;
}

Decent::Net::LocalMessageQueue::~LocalMessageQueue()
{
	DestructMsgQueue(m_msgQ, m_name, m_isOwner);
}
