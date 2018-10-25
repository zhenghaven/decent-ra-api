#pragma once

#include <string>
//#include <atomic>

#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/ipc/message_queue.hpp>

#include "../Common.h"

template<typename T>
class SharedObject
{
private:
	static boost::interprocess::shared_memory_object ConstructObj(const std::string& objName, const bool isCreate)
	{
		if (isCreate)
		{
			boost::interprocess::shared_memory_object::remove(objName.c_str());
			boost::interprocess::shared_memory_object retObj(boost::interprocess::create_only, objName.c_str(), boost::interprocess::read_write);
			retObj.truncate(sizeof(T));
			LOGI("Created shared object, %s.\n", objName.c_str());
			return std::move(retObj);
		}
		else
		{
			boost::interprocess::shared_memory_object retObj(boost::interprocess::open_only, objName.c_str(), boost::interprocess::read_write);
			return std::move(retObj);
		}
	}

	static boost::interprocess::mapped_region ContructMap(const boost::interprocess::shared_memory_object& sharedObj)
	{
		return boost::interprocess::mapped_region(sharedObj, boost::interprocess::read_write);
	}

public:
	SharedObject(const std::string& objName, const bool isCreate) :
		m_sharedObj(ConstructObj(objName, isCreate)),
		m_mapReg(ContructMap(m_sharedObj)),
		m_objPtr(isCreate ? (new (m_mapReg.get_address()) T) : static_cast<T*>(m_mapReg.get_address())),
		m_isOwner(isCreate)
	{
	}

	SharedObject(const SharedObject& other) = delete;
	SharedObject(SharedObject&& other) :
		m_sharedObj(std::move(other.m_sharedObj)),
		m_mapReg(std::move(other.m_mapReg)),
		m_objPtr(other.m_objPtr),
		m_isOwner(other.m_isOwner)
	{
		other.m_objPtr = nullptr;
		other.m_isOwner = false;
	}

	T& GetObject() { return *m_objPtr; }

	const T& GetObject() const { return *m_objPtr; }

	~SharedObject()
	{
		std::string objName;
		if (m_isOwner)
		{
			objName = m_sharedObj.get_name();
		}
		
		{
			boost::interprocess::shared_memory_object tmpObj;
			boost::interprocess::mapped_region tmpMap;
			tmpObj.swap(m_sharedObj);
			tmpMap.swap(m_mapReg);
		}

		if (m_isOwner)
		{
			bool isClosed = boost::interprocess::shared_memory_object::remove(objName.c_str());
			LOGI("Attempted to close shared object, %s - %s!\n", objName.c_str(), isClosed ? "Successful!" : "Failed!");
		}
	}

private:
	boost::interprocess::shared_memory_object m_sharedObj;
	boost::interprocess::mapped_region m_mapReg;
	T* m_objPtr;
	bool m_isOwner;
};

struct LocalConnectStruct
{
private:
	volatile uint8_t m_isClosed;

public:
	static constexpr size_t UUID_STR_LEN = (16 * 2) + 1;


	boost::interprocess::interprocess_mutex m_connectLock;
	boost::interprocess::interprocess_mutex m_writeLock;

	boost::interprocess::interprocess_condition m_connectSignal;
	boost::interprocess::interprocess_condition m_idReadySignal;

	char m_msg[UUID_STR_LEN];
	volatile uint8_t m_isMsgReady;

	LocalConnectStruct() noexcept :
		m_isClosed(false),
		m_msg{ 0 },
		m_isMsgReady(false)
	{}

	void SetClose() volatile noexcept { m_isClosed = 1; }

	bool IsClosed() const volatile noexcept { return m_isClosed; }
};

struct LocalSessionStruct
{
private:
	volatile uint8_t m_isClosed;

public:
	static constexpr size_t MSG_SIZE = 5;
	static constexpr char const NAME_S2C_POSTFIX[] = "S2C_S";
	static constexpr char const NAME_C2S_POSTFIX[] = "C2S_S";

	boost::interprocess::interprocess_mutex m_msgLock;
	boost::interprocess::interprocess_condition m_readySignal;

	volatile uint8_t m_isMsgReady;

	LocalSessionStruct() noexcept:
		m_isClosed(false),
		m_isMsgReady(false)
	{
	}

	void SetClose() volatile noexcept { m_isClosed = 1; }

	bool IsClosed() const volatile noexcept { return m_isClosed; }
};

struct LocalMessageQueue
{
private:
	static boost::interprocess::message_queue* ConstructQueue(const std::string& name, const bool isOwner)
	{
		if (isOwner)
		{
			boost::interprocess::message_queue::remove(name.c_str());
			LOGI("Created msg queue, %s.\n", name.c_str());
			return new boost::interprocess::message_queue(boost::interprocess::create_only, name.c_str(),
				MSG_SIZE, sizeof(uint8_t));
		}
		else
		{
			return new boost::interprocess::message_queue(boost::interprocess::open_only, name.c_str());
		}
	}

	boost::interprocess::message_queue* m_msgQ;
	bool m_isOwner;
	std::string m_name;

public:
	static constexpr unsigned int DEFAULT_PRIORITY = 0;
	static constexpr size_t CHUNK_SIZE = sizeof(uint8_t);
	static constexpr size_t MSG_SIZE = LocalSessionStruct::MSG_SIZE;
	static constexpr char const NAME_S2C_POSTFIX[] = "S2C_M";
	static constexpr char const NAME_C2S_POSTFIX[] = "C2S_M";

	LocalMessageQueue(const std::string& name, const bool isOwner) :
		m_msgQ(ConstructQueue(name, isOwner)),
		m_isOwner(isOwner),
		m_name(name)
	{
	}

	LocalMessageQueue(const LocalMessageQueue& other) = delete;
	LocalMessageQueue(LocalMessageQueue&& other) :
		m_msgQ(other.m_msgQ),
		m_isOwner(other.m_isOwner),
		m_name(std::move(other.m_name))
	{
		other.m_msgQ = nullptr;
		m_isOwner = false;
	}

	~LocalMessageQueue()
	{
		delete m_msgQ;

		if (m_isOwner)
		{
			bool isClosed = boost::interprocess::message_queue::remove(m_name.c_str());
			LOGI("Attempted to close msg queue, %s - %s!\n", m_name.c_str(), isClosed ? "Successful!" : "Failed!");
		}
	}

	boost::interprocess::message_queue& GetQ() { return *m_msgQ; }
	const boost::interprocess::message_queue& GetQ() const { return *m_msgQ; }
};
