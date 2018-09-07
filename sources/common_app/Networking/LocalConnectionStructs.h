#pragma once

#include <string>
//#include <atomic>

#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include "../Common.h"

template<typename T>
class SharedObject
{
public:
	SharedObject(const std::string& objName, const bool isCreate) :
		m_isOwner(isCreate)
	{
		if (isCreate)
		{
			shared_memory_object::remove(objName.c_str());
			m_sharedObj = new boost::interprocess::shared_memory_object(create_only, objName.c_str(), read_write);
			m_sharedObj->truncate(sizeof(T));
			LOGI("Created shared object, %s.\n", objName.c_str());
		}
		else
		{
			m_sharedObj = new boost::interprocess::shared_memory_object(open_only, objName.c_str(), read_write);
		}

		m_mapReg = new mapped_region(*m_sharedObj, read_write);

		if (isCreate)
		{
			m_objPtr = new (m_mapReg->get_address()) T;
		}
		else
		{
			m_objPtr = static_cast<T*>(m_mapReg->get_address());
		}
	}

	SharedObject(const SharedObject& other) = delete;
	SharedObject(SharedObject&& other) = delete;
	//SharedObject(SharedObject&& other) noexcept :
	//	m_sharedObj(other.m_sharedObj),
	//	m_mapReg(other.m_mapReg),
	//	m_objPtr(other.m_objPtr),
	//	m_isOwner(other.m_isOwner)
	//{
	//	other.m_sharedObj = nullptr;
	//	other.m_mapReg = nullptr;
	//	other.m_objPtr = nullptr;
	//	other.m_isOwner = false;
	//}

	T& GetObject()
	{
		return *m_objPtr;
	}

	const T& GetObject() const
	{
		return *m_objPtr;
	}

	~SharedObject()
	{
		std::string objName;
		if (m_isOwner)
		{
			objName = m_sharedObj->get_name();
		}
		
		delete m_sharedObj;
		delete m_mapReg;

		if (m_isOwner)
		{
			bool isClosed = shared_memory_object::remove(objName.c_str());
			LOGI("Attempted to close shared object, %s - %s!\n", objName.c_str(), isClosed ? "Successful!" : "Failed!");
		}
	}

	//bool IsValid() const
	//{
	//	return m_objPtr && m_mapReg;
	//}

private:
	boost::interprocess::shared_memory_object* m_sharedObj;
	boost::interprocess::mapped_region* m_mapReg;
	T* m_objPtr;
	bool m_isOwner;
};

struct LocalConnectStruct
{
private:
	//std::atomic<uint8_t> m_isClosed;
	volatile uint8_t m_isClosed;

public:
	enum { UUID_STR_LEN = (16 * 2) + 1 };


	boost::interprocess::interprocess_mutex m_connectLock;
	boost::interprocess::interprocess_mutex m_writeLock;

	boost::interprocess::interprocess_condition m_connectSignal;
	boost::interprocess::interprocess_condition m_idReadySignal;

	char m_msg[UUID_STR_LEN];

	LocalConnectStruct() noexcept :
		m_isClosed(false),
		m_msg{ 0 }
	{}

	void SetClose() volatile noexcept
	{
		m_isClosed = 1;
	}

	bool IsClosed() const volatile noexcept
	{
		return m_isClosed;
	}
};

struct LocalSessionStruct
{
private:
	//std::atomic<uint8_t> m_isClosed;
	volatile uint8_t m_isClosed;

public:
	enum { MSG_SIZE = 65536 };

	boost::interprocess::interprocess_mutex m_msgLock;
	boost::interprocess::interprocess_condition m_emptySignal;
	boost::interprocess::interprocess_condition m_readySignal;

	volatile uint8_t m_isMsgReady;
	volatile uint64_t m_totalSize;
	volatile uint32_t m_sentSize;
	uint8_t m_msg[MSG_SIZE];

	LocalSessionStruct() noexcept:
		m_isClosed(false),
		m_isMsgReady(false),
		m_totalSize(0),
		m_sentSize(0),
		m_msg{ 0 }
	{
		static_assert(sizeof(m_sentSize) < MSG_SIZE, "The MSG_SIZE must not exceed the size of m_sentSize!");
	}

	void SetClose() volatile noexcept
	{
		m_isClosed = 1;
	}

	bool IsClosed() const volatile noexcept
	{
		return m_isClosed;
	}
};
