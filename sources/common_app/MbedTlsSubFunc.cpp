#include "../common/MbedTlsSubFunc.h"

#include <mutex>

struct MyMutexStruct
{
	std::mutex m_mutex;
	std::unique_lock<std::mutex> m_lock;

	MyMutexStruct() :
		m_mutex(),
		m_lock(m_mutex, std::defer_lock)
	{
	}
};

void DecentMbedTls::mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		mutex->m_ptr)
	{
		return;
	}

	mutex->m_ptr = new MyMutexStruct;
}

void DecentMbedTls::mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		!mutex->m_ptr)
	{
		return;
	}

	MyMutexStruct* myMutex = reinterpret_cast<MyMutexStruct*>(mutex->m_ptr);
	delete myMutex;
	mutex->m_ptr = nullptr;
}

int DecentMbedTls::mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		!mutex->m_ptr)
	{
		return -1;
	}

	MyMutexStruct* myMutex = reinterpret_cast<MyMutexStruct*>(mutex->m_ptr);
	myMutex->m_lock.lock();
	return 0;
}

int DecentMbedTls::mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		!mutex->m_ptr)
	{
		return -1;
	}

	MyMutexStruct* myMutex = reinterpret_cast<MyMutexStruct*>(mutex->m_ptr);
	myMutex->m_lock.unlock();
	return 0;
}
