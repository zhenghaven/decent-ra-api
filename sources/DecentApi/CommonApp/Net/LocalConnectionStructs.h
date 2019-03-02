#pragma once

#include <string>

#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>

#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace boost
{
	namespace interprocess
	{
		class shared_memory_object;
		class mapped_region;
		class interprocess_mutex;
		class interprocess_condition;
	}
}

namespace Decent
{
	namespace Net
	{
		std::unique_ptr<boost::interprocess::shared_memory_object> ConstructSharedObj(const std::string& objName, const size_t size, const bool isCreate);
		std::unique_ptr<boost::interprocess::mapped_region> ContructSharedMap(const boost::interprocess::shared_memory_object& sharedObj);
		void DestructSharedMap(std::unique_ptr<boost::interprocess::mapped_region>& mapPtr) noexcept;
		void DestructSharedObj(std::unique_ptr<boost::interprocess::shared_memory_object>& objPtr, const bool isOwner) noexcept;

		template<typename T>
		class SharedObject
		{
		public:
			SharedObject(const std::string& objName, const bool isCreate) :
				m_sharedObj(ConstructSharedObj(objName, sizeof(T), isCreate)),
				m_mapReg(ContructSharedMap(*m_sharedObj)),
				m_objPtr(isCreate ? (new (m_mapReg->get_address()) T) : static_cast<T*>(m_mapReg->get_address())),
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
				DestructSharedMap(m_mapReg);
				DestructSharedObj(m_sharedObj, m_isOwner);
			}

		private:
			std::unique_ptr<boost::interprocess::shared_memory_object> m_sharedObj;
			std::unique_ptr<boost::interprocess::mapped_region> m_mapReg;
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

		public:
			LocalConnectStruct() noexcept :
			m_isClosed(false),
				m_msg{ 0 },
				m_isMsgReady(false)
			{}

			void SetClose() volatile noexcept { m_isClosed = 1; }

			bool IsClosed() const volatile noexcept { return m_isClosed; }
		};

#define SESSION_NAME_S2C_POSTFIX "S2C_S"
#define SESSION_NAME_C2S_POSTFIX "C2S_S"

		struct LocalSessionStruct
		{
		private:
			volatile uint8_t m_isClosed;

		public:
			static constexpr size_t MSG_SIZE = 5;

			boost::interprocess::interprocess_mutex m_msgLock;
			boost::interprocess::interprocess_condition m_readySignal;

			volatile uint8_t m_isMsgReady;

		public:
			LocalSessionStruct() noexcept:
			m_isClosed(false),
				m_isMsgReady(false)
			{}

			void SetClose() volatile noexcept { m_isClosed = 1; }

			bool IsClosed() const volatile noexcept { return m_isClosed; }
		};

#define QUEUE_NAME_S2C_POSTFIX "S2C_M"
#define QUEUE_NAME_C2S_POSTFIX "C2S_M"

		std::unique_ptr<boost::interprocess::message_queue> ConstructMsgQueue(const std::string& name, const bool isOwner);
		void DestructMsgQueue(std::unique_ptr<boost::interprocess::message_queue>& queuePtr, const std::string& name, const bool isOwner) noexcept;

		class LocalMessageQueue
		{
		public:
			static constexpr unsigned int DEFAULT_PRIORITY = 0;
			static constexpr size_t CHUNK_SIZE = sizeof(uint8_t);
			static constexpr size_t MSG_SIZE = LocalSessionStruct::MSG_SIZE;

			LocalMessageQueue(const std::string& name, const bool isOwner);

			LocalMessageQueue(const LocalMessageQueue& other) = delete;
			LocalMessageQueue(LocalMessageQueue&& other) noexcept;

			~LocalMessageQueue();

			boost::interprocess::message_queue& GetQ() { return *m_msgQ; }
			const boost::interprocess::message_queue& GetQ() const { return *m_msgQ; }

		private:
			std::unique_ptr<boost::interprocess::message_queue> m_msgQ;
			std::string m_name;
			bool m_isOwner;
		};
	}
}
