#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>

struct LocalConnectStruct
{
	enum { UUID_STR_LEN = (16 * 2) + 1 };

	//uint8_t m_isListening;
	uint8_t m_isClosed;

	boost::interprocess::interprocess_mutex m_connectLock;
	boost::interprocess::interprocess_mutex m_writeLock;

	boost::interprocess::interprocess_condition m_connectSignal;
	boost::interprocess::interprocess_condition m_idReadySignal;

	char m_msg[UUID_STR_LEN];

	LocalConnectStruct() :
		//m_isListening(false),
		m_isClosed(false),
		m_msg{ 0 }
	{}
};

struct LocalSessionStruct
{
	enum { MSG_SIZE = 65536 };

	boost::interprocess::interprocess_mutex m_msgLock;
	boost::interprocess::interprocess_condition m_msgSignal;

	uint8_t m_isClosed;
	uint8_t m_isMsgReady;
	uint64_t m_totalSize;
	uint32_t m_sentSize;
	uint8_t m_msg[MSG_SIZE];

	LocalSessionStruct() :
		m_isClosed(false),
		m_isMsgReady(false),
		m_totalSize(0),
		m_sentSize(0),
		m_msg{ 0 }
	{
		static_assert(sizeof(m_sentSize) < MSG_SIZE, "The MSG_SIZE must not exceed the size of m_sentSize!");
	}
};
