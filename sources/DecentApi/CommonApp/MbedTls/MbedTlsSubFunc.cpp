#include "../../Common/MbedTls/MbedTlsSubFunc.h"

#include <mutex>
#include <memory>

#include "../../Common/Common.h"

using namespace Decent;

struct MyMutexStruct
{
	std::mutex m_mutex;
	std::unique_ptr<std::unique_lock<std::mutex> > m_lock;

	MyMutexStruct() :
		m_mutex(),
		m_lock()
	{
	}
};

void MbedTls::mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex)
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_init.");
		return;
	}

	mutex->m_ptr = new MyMutexStruct();
}

void MbedTls::mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		!mutex->m_ptr)
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_free.");
		return;
	}

	MyMutexStruct* myMutex = reinterpret_cast<MyMutexStruct*>(mutex->m_ptr);
	delete myMutex;
	mutex->m_ptr = nullptr;
}

int MbedTls::mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		!mutex->m_ptr)
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_lock.");
		return -1;
	}

	MyMutexStruct* myMutex = reinterpret_cast<MyMutexStruct*>(mutex->m_ptr);

	try
	{
		std::unique_ptr<std::unique_lock<std::mutex> > lockPtr = std::make_unique<std::unique_lock<std::mutex> >(myMutex->m_mutex);
		myMutex->m_lock = std::move(lockPtr);
	}
	catch (const std::exception&)
	{
		PRINT_I("MbedTLS Failed to lock the mutex.");
		return -1;
	}

	return 0;
}

int MbedTls::mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		!mutex->m_ptr)
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_unlock.");
		return -1;
	}

	MyMutexStruct* myMutex = reinterpret_cast<MyMutexStruct*>(mutex->m_ptr);

	try
	{
		myMutex->m_lock.reset();
	}
	catch (const std::exception&)
	{
		PRINT_I("MbedTLS Failed to unlock the mutex.");
		return -1;
	}

	return 0;
}
